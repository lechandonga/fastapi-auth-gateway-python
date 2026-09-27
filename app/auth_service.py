"""认证服务门面：登录、刷新（轮换+重放检测）、登出、访问凭据校验。

并发语义：刷新/重放判定在同一把 Store 全局锁内原子完成，
同一刷新凭据并发使用时恰好一次成功，其余识别为重放并吊销整个会话。
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from .config import AuthConfig
from .errors import (
    AccessTokenExpired,
    AccessTokenInvalid,
    AccessTokenMissing,
    InvalidCredentials,
    RefreshTokenExpired,
    RefreshTokenInvalid,
    RefreshTokenReplayed,
    SessionRevoked,
)
from .models import SessionRecord, User
from .ratelimit import LoginThrottle
from .security import (
    generate_token,
    token_fingerprint,
    verify_password,
)
from .store import Store

logger = logging.getLogger("auth.service")

# 对不存在用户使用一个一次性伪哈希，保持与真实用户近似的校验耗时，
# 避免通过响应时间枚举用户名。
_DUMMY_HASH = (
    "pbkdf2_sha256$1$00000000000000000000000000000000$"
    "0000000000000000000000000000000000000000000000000000000000000000"
)


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 0
    refresh_expires_in: int = 0


class AuthService:
    def __init__(self, store: Store, config: AuthConfig) -> None:
        self.store = store
        self.config = config
        self.throttle = LoginThrottle(store, config)

    def _now(self) -> float:
        return time.time()

    # ---- 登录 ----
    def login(self, username: str, password: str) -> TokenPair:
        # 锁定检查本身记录“判定依据”
        self.throttle.ensure_not_locked(username)

        user = self.store.get_user(username)
        stored_hash = user.password_hash if user is not None else _DUMMY_HASH
        password_ok = verify_password(password, stored_hash, self.config)

        if user is None or not password_ok:
            self.throttle.register_failure(username)
            logger.warning(
                "登录失败: username=%s user_found=%s password_ok=%s",
                username,
                user is not None,
                password_ok,
            )
            # 无论用户不存在还是密码错误，对外结论完全一致
            raise InvalidCredentials(reason="bad_username_or_password")

        self.throttle.reset(username)
        pair = self._issue_session(user)
        logger.info(
            "登录成功并签发会话: username=%s access_ttl=%ss refresh_ttl=%ss",
            user.username,
            self.config.access_token_ttl_seconds,
            self.config.refresh_token_ttl_seconds,
        )
        return pair

    # ---- 刷新（轮换 + 重放检测，全程持锁） ----
    def refresh(self, refresh_token: str) -> TokenPair:
        if not refresh_token or not isinstance(refresh_token, str):
            raise RefreshTokenInvalid(reason="empty_token")

        fingerprint = token_fingerprint(refresh_token)
        now = self._now()

        with self.store.lock():
            # 1) 优先查墓碑：旧/已用刷新凭据 => 重放
            replay_session = self.store.find_replay_session(fingerprint)
            if replay_session is not None:
                if not replay_session.revoked:
                    self.store.revoke_session(replay_session, "refresh_token_replay")
                logger.error(
                    "刷新凭据重放: session_id=%s 已吊销=%s reason=%s",
                    replay_session.session_id,
                    replay_session.revoked,
                    replay_session.revoke_reason,
                )
                raise RefreshTokenReplayed(reason=replay_session.revoke_reason or "replay")

            # 2) 当前有效索引
            session = self.store.find_session_by_refresh(fingerprint)
            if session is None:
                logger.warning("刷新失败: 刷新凭据无法识别 fingerprint_prefix=%s", fingerprint[:12])
                raise RefreshTokenInvalid(reason="unknown_token")

            if session.revoked:
                logger.warning("刷新被拒: 会话已吊销 session_id=%s", session.session_id)
                raise SessionRevoked(
                    f"会话已失效（{session.revoke_reason}）",
                    reason=session.revoke_reason or "revoked",
                )

            if now >= session.refresh_expires_at:
                logger.info(
                    "刷新失败: 刷新凭据已过期 session_id=%s expired_at=%s",
                    session.session_id,
                    session.refresh_expires_at,
                )
                raise RefreshTokenExpired(reason="ttl_expired")

            # 3) 通过：原子轮换
            user = self.store.get_user(session.username)
            if user is None:
                # 用户被删除等极端情况：归一化处理而不是透出底层异常
                raise InvalidCredentials(reason="user_no_longer_exists")

            pair = self._rotate_session(session, user, now)
            logger.info(
                "刷新成功并轮换凭据: username=%s session_id=%s",
                user.username,
                session.session_id,
            )
            return pair

    # ---- 登出 ----
    def logout(self, refresh_token: str) -> None:
        if not refresh_token:
            raise RefreshTokenInvalid(reason="empty_token")
        fingerprint = token_fingerprint(refresh_token)
        with self.store.lock():
            session = self.store.find_session_by_refresh(fingerprint)
            if session is None:
                # 幂等：可能已轮换（在墓碑中）或无法识别
                replay = self.store.find_replay_session(fingerprint)
                if replay is not None:
                    logger.info(
                        "登出忽略: 凭据已轮换 session_id=%s revoked=%s",
                        replay.session_id,
                        replay.revoked,
                    )
                    return
                raise RefreshTokenInvalid(reason="unknown_token")
            self.store.revoke_session(session, "user_logout")
            logger.info(
                "登出成功，会话已吊销: session_id=%s already_revoked=%s",
                session.session_id,
                session.revoke_reason != "user_logout",
            )

    # ---- 访问凭据校验 ----
    def authenticate_access(self, access_token: str | None) -> tuple[User, SessionRecord]:
        if not access_token:
            logger.info("访问被拒: 请求未携带访问凭据")
            raise AccessTokenMissing(reason="no_authorization_header")

        fingerprint = token_fingerprint(access_token)
        now = self._now()

        with self.store.lock():
            session = self.store.find_session_by_access(fingerprint)
            if session is None:
                logger.warning(
                    "访问被拒: 访问凭据无法识别 fingerprint_prefix=%s", fingerprint[:12]
                )
                raise AccessTokenInvalid(reason="unknown_or_rotated_token")
            if session.revoked:
                logger.warning(
                    "访问被拒: 会话已吊销 session_id=%s reason=%s",
                    session.session_id,
                    session.revoke_reason,
                )
                raise SessionRevoked(
                    f"会话已失效（{session.revoke_reason}）",
                    reason=session.revoke_reason or "revoked",
                )
            if now >= session.access_expires_at:
                logger.info(
                    "访问被拒: 访问凭据已过期 session_id=%s expired_at=%s",
                    session.session_id,
                    session.access_expires_at,
                )
                raise AccessTokenExpired(reason="ttl_expired")

            user = self.store.get_user(session.username)
            if user is None:
                raise AccessTokenInvalid(reason="user_no_longer_exists")
            logger.info(
                "访问凭据校验通过: username=%s session_id=%s", user.username, session.session_id
            )
            return user, session

    # ---- 内部：签发与轮换 ----
    def _new_credentials(self, now: float) -> tuple[str, str, str, str, float, float]:
        access = generate_token(self.config)
        refresh = generate_token(self.config)
        access_hash = token_fingerprint(access)
        refresh_hash = token_fingerprint(refresh)
        access_exp = now + self.config.access_token_ttl_seconds
        refresh_exp = now + self.config.refresh_token_ttl_seconds
        return access, refresh, access_hash, refresh_hash, access_exp, refresh_exp

    def _issue_session(self, user: User) -> TokenPair:
        now = self._now()
        access, refresh, access_hash, refresh_hash, access_exp, refresh_exp = (
            self._new_credentials(now)
        )
        record = SessionRecord(
            username=user.username,
            refresh_token_hash=refresh_hash,
            refresh_expires_at=refresh_exp,
            access_token_hash=access_hash,
            access_expires_at=access_exp,
        )
        with self.store.lock():
            self.store.add_session(record)
        logger.info("创建会话: session_id=%s username=%s", record.session_id, user.username)
        return TokenPair(
            access_token=access,
            refresh_token=refresh,
            expires_in=self.config.access_token_ttl_seconds,
            refresh_expires_in=self.config.refresh_token_ttl_seconds,
        )

    def _rotate_session(self, session: SessionRecord, user: User, now: float) -> TokenPair:
        access, refresh, access_hash, refresh_hash, access_exp, refresh_exp = (
            self._new_credentials(now)
        )
        self.store.rotate_credentials(
            session,
            new_access_hash=access_hash,
            new_access_expires_at=access_exp,
            new_refresh_hash=refresh_hash,
            new_refresh_expires_at=refresh_exp,
        )
        return TokenPair(
            access_token=access,
            refresh_token=refresh,
            expires_in=self.config.access_token_ttl_seconds,
            refresh_expires_in=self.config.refresh_token_ttl_seconds,
        )
