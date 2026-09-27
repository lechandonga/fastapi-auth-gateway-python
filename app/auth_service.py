"""认证服务：登录签发、刷新轮换与重放检测、账号级连续失败限制。

并发安全约定：任何“读-判-写”的复合流程都整体放在 store.lock() 内
（可重入 RLock），因此：
  - 并发登录时失败计数与锁定判定不会丢更新，且只锁定命中的账号；
  - 并发刷新时同一刷新凭据有且仅有一次成功，其余全部判定为重放。
"""

import logging
import uuid

from app.config import Settings
from app.errors import (
    AccountLockedError,
    InvalidCredentialsError,
    RefreshReplayError,
    SessionRevokedError,
    TokenInvalidError,
)
from app.models import (
    IssuedCredentials,
    Principal,
    RefreshTokenRecord,
    Session,
    now,
)
from app.security import (
    decode_access_token,
    encode_access_token,
    generate_opaque_token,
    hash_token,
    verify_password,
)
from app.storage import InMemoryStore

logger = logging.getLogger("auth.service")


class AuthService:
    def __init__(self, store: InMemoryStore, settings: Settings) -> None:
        self.store = store
        self.settings = settings

    # ------------------------------------------------------------------ 登录
    def login(self, username: str, password: str) -> IssuedCredentials:
        """校验口令、检查账号锁定，成功后建立会话并签发一对凭据。"""
        store = self.store
        with store.lock:
            locked, remaining = store.is_locked(username)
            if locked:
                # 锁定期间直接拒绝，不校验口令，避免通过响应猜测口令正确性；
                # 且该状态只按提交的用户名隔离，绝不影响其他账号。
                logger.info(
                    "login.denied user=%s reason=account_locked remaining=%ss",
                    username, remaining)
                raise AccountLockedError(
                    f"账号已被临时锁定，请 {remaining} 秒后重试",
                    reason="account_locked",
                    retry_after=remaining)

            user = store.get_user(username)
            valid = bool(user) and user.enabled and verify_password(
                password, user.password_hash)
            if not valid:
                record = store.register_failure(
                    username,
                    self.settings.login_max_failures,
                    self.settings.login_lock_seconds)
                # 统一错误措辞，避免账号枚举；reason 对内可区分具体原因。
                if user is None:
                    reason = "unknown_username"
                elif not user.enabled:
                    reason = "account_disabled"
                else:
                    reason = "bad_password"
                logger.info(
                    "login.failed user=%s reason=%s consecutive_failures=%s",
                    username, reason, record.consecutive_failures)
                raise InvalidCredentialsError(
                    "用户名或口令错误", reason=reason)

            # 成功：清零失败计数，建立一个全新的会话族。
            store.reset_failures(username)
            issued = self._issue(username)
            logger.info(
                "login.ok user=%s session_id=%s family_id=%s",
                username, issued.session_id, issued.family_id)
            return issued

    # ------------------------------------------------------------------ 刷新
    def refresh(self, refresh_token: str) -> IssuedCredentials:
        """消费刷新凭据：旧凭据失效并签发新一对凭据（同一凭据族轮换）。"""
        store = self.store
        token_hash = hash_token(refresh_token)

        with store.lock:
            record = store.get_refresh_token(token_hash)
            if record is None:
                # 从未签发过（伪造/拼写错误），与“重放”明确区分。
                logger.info("refresh.denied reason=unknown_refresh_token")
                raise TokenInvalidError("刷新凭据无效", reason="refresh_token_unknown")

            session = store.get_session(record.session_id)

            # 1) 重放：该凭据此前已被成功消费过（轮换或重复/并发使用）。
            if record.used:
                logger.warning(
                    "refresh.replay user=%s family_id=%s reason=refresh_token_reused "
                    "session_id=%s -> revoke whole family",
                    record.username, record.family_id, record.session_id)
                store.revoke_family(record.family_id, reason="refresh_replay")
                raise RefreshReplayError(
                    "检测到刷新凭据重放，该会话已整体失效",
                    reason="refresh_token_reused")

            # 2) 会话/凭据族已被撤销。若撤销原因是此前的重放，同样归类为重放，
            #    从而给出可区分且一致的结论。
            family_revoked = record.revoked or (session is not None and session.revoked)
            if family_revoked:
                revoke_reason = session.revoke_reason if session else "refresh_replay"
                if revoke_reason == "refresh_replay":
                    logger.warning(
                        "refresh.replay user=%s family_id=%s "
                        "reason=family_revoked_by_replay",
                        record.username, record.family_id)
                    raise RefreshReplayError(
                        "会话此前已因刷新凭据重放被整体失效",
                        reason="family_revoked_by_replay")
                logger.info(
                    "refresh.denied user=%s reason=session_revoked detail=%s",
                    record.username, revoke_reason)
                raise SessionRevokedError("会话已失效", reason=revoke_reason or "revoked")

            if session is None:
                # 数据不一致不应发生；作为已撤销处理，不透出内部细节。
                logger.warning(
                    "refresh.denied reason=session_missing session_id=%s",
                    record.session_id)
                raise SessionRevokedError("会话已失效", reason="session_missing")

            # 3) 过期：不是重放，不牵连会话族，要求重新登录。
            if record.expires_at <= now():
                logger.info(
                    "refresh.denied user=%s reason=refresh_expired session_id=%s",
                    record.username, record.session_id)
                raise TokenInvalidError("刷新凭据已过期", reason="refresh_expired")

            # 4) 合法轮换：原子地把旧凭据标记为已使用，再签发新一对凭据。
            #    临界区内没有 await/IO 会释放锁，故并发请求中只有一个能走到这里。
            record.used = True
            issued = self._issue(record.username, family_id=record.family_id)
            logger.info(
                "refresh.ok user=%s family_id=%s old_session=%s new_session=%s",
                record.username, record.family_id,
                record.session_id, issued.session_id)
            return issued

    # ------------------------------------------------------- 访问凭据认证
    def authenticate_access_token(self, token: str) -> Principal:
        """校验访问凭据并检查会话即时状态，产出 Principal。"""
        payload = decode_access_token(token, self.settings)
        session_id = payload["sid"]
        session = self.store.get_session(session_id)
        if session is None or session.revoked:
            reason = session.revoke_reason if session else "session_missing"
            # 撤销即时生效：即使访问凭据尚未过期也立即拒绝；
            # 而角色/权限调整则以签发时的快照为准，直到下次刷新/登录。
            if reason == "refresh_replay":
                logger.info(
                    "access.denied user=%s reason=family_revoked_by_replay",
                    payload["sub"])
                raise RefreshReplayError(
                    "会话已因刷新凭据重放被整体失效",
                    reason="family_revoked_by_replay")
            logger.info("access.denied user=%s reason=session_revoked detail=%s",
                        payload["sub"], reason)
            raise SessionRevokedError("会话已失效", reason=reason or "revoked")

        return Principal(
            username=payload["sub"],
            session_id=session_id,
            family_id=payload["fid"],
            roles=frozenset(payload.get("roles", [])),
            permissions=frozenset(payload.get("permissions", [])),
        )

    # ------------------------------------------------------------- 管理操作
    def revoke_session(self, session_id: str, reason: str = "admin_revoke") -> None:
        """撤销会话及其凭据族，访问凭据与刷新凭据都会立即失效。"""
        session = self.store.get_session(session_id)
        if session is None:
            return
        self.store.revoke_family(session.family_id, reason=reason)
        logger.info("session.revoked session_id=%s reason=%s", session_id, reason)

    # ------------------------------------------------------------- 内部方法
    def _issue(self, username: str, family_id: str | None = None) -> IssuedCredentials:
        """创建会话/凭据对并签发 JWT。调用方必须持有 store.lock()。"""
        store = self.store
        user = store.get_user(username)
        if user is None:  # 防御性分支：正常流程中调用方已确认用户存在
            raise InvalidCredentialsError("用户名或口令错误", reason="unknown_username")

        if family_id is None:
            family_id = uuid.uuid4().hex
        session_id = uuid.uuid4().hex
        issued_at = now()
        session = Session(
            session_id=session_id,
            family_id=family_id,
            username=username,
            created_at=issued_at,
        )
        store.put_session(session)

        refresh_token = generate_opaque_token()
        refresh_record = RefreshTokenRecord(
            token_hash=hash_token(refresh_token),
            session_id=session_id,
            family_id=family_id,
            username=username,
            issued_at=issued_at,
            expires_at=issued_at + self.settings.refresh_token_ttl_seconds,
        )
        store.put_refresh_token(refresh_record)

        principal = Principal(
            username=username,
            session_id=session_id,
            family_id=family_id,
            roles=frozenset(user.roles),
            permissions=frozenset(user.permissions),
        )
        access_token, access_ttl = encode_access_token(principal, self.settings)
        return IssuedCredentials(
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_in=access_ttl,
            refresh_expires_in=self.settings.refresh_token_ttl_seconds,
            session_id=session_id,
            family_id=family_id,
        )
