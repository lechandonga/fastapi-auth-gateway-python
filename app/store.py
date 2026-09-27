"""线程安全的本地内存存储：用户、会话、刷新墓碑、账号失败计数。

一致性约定：
- 所有公开方法内部持有同一把可重入锁；需要跨多个操作原子完成的流程
  （刷新轮换/重放判定）由服务层通过 ``with store.lock():`` 包裹。
- 刷新凭据轮换时，旧刷新指纹进入全局墓碑索引 ``_used_refresh_index``，
  因此任何旧/已用凭据再次出现都能被定位到原会话并触发整体吊销。
- 原始令牌绝不落库，只存 SHA-256 指纹。
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from .models import SessionRecord, User
from .models_roles import Role


class Store:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users: dict[str, User] = {}
        self._sessions: dict[str, SessionRecord] = {}
        self._access_index: dict[str, str] = {}
        self._refresh_index: dict[str, str] = {}
        # 已轮换作废的刷新指纹 -> session_id（重放检测）
        self._used_refresh_index: dict[str, str] = {}
        self._fail_counts: dict[str, int] = {}
        self._locked_until: dict[str, float] = {}

    @contextmanager
    def lock(self) -> Iterator[None]:
        with self._lock:
            yield

    # ---- 用户 ----
    def add_user(self, user: User) -> None:
        with self._lock:
            self._users[user.username] = user

    def get_user(self, username: str) -> User | None:
        with self._lock:
            return self._users.get(username)

    def set_roles(self, username: str, roles: frozenset[Role]) -> None:
        with self._lock:
            user = self._users.get(username)
            if user is not None:
                user.roles = roles

    # ---- 会话 ----
    def add_session(self, record: SessionRecord) -> None:
        with self._lock:
            self._sessions[record.session_id] = record
            self._access_index[record.access_token_hash] = record.session_id
            self._refresh_index[record.refresh_token_hash] = record.session_id

    def get_session(self, session_id: str) -> SessionRecord | None:
        with self._lock:
            return self._sessions.get(session_id)

    def find_session_by_refresh(self, refresh_hash: str) -> SessionRecord | None:
        """按“当前有效”的刷新指纹定位会话。"""
        with self._lock:
            sid = self._refresh_index.get(refresh_hash)
            return self._sessions.get(sid) if sid is not None else None

    def find_session_by_access(self, access_hash: str) -> SessionRecord | None:
        with self._lock:
            sid = self._access_index.get(access_hash)
            return self._sessions.get(sid) if sid is not None else None

    def find_replay_session(self, used_refresh_hash: str) -> SessionRecord | None:
        """在墓碑索引中定位曾被轮换作废的刷新凭据所属会话。"""
        with self._lock:
            sid = self._used_refresh_index.get(used_refresh_hash)
            return self._sessions.get(sid) if sid is not None else None

    def rotate_credentials(
        self,
        session: SessionRecord,
        *,
        new_access_hash: str,
        new_access_expires_at: float,
        new_refresh_hash: str,
        new_refresh_expires_at: float,
    ) -> None:
        """原子轮换：旧刷新指纹入墓碑，旧访问/刷新索引摘除，新指纹建索引。

        调用方必须持有 ``store.lock()``。
        """
        with self._lock:
            old_refresh = session.refresh_token_hash
            old_access = session.access_token_hash

            session.used_refresh_hashes.add(old_refresh)
            self._used_refresh_index[old_refresh] = session.session_id
            self._refresh_index.pop(old_refresh, None)
            self._access_index.pop(old_access, None)

            session.access_token_hash = new_access_hash
            session.access_expires_at = new_access_expires_at
            session.refresh_token_hash = new_refresh_hash
            session.refresh_expires_at = new_refresh_expires_at

            self._access_index[new_access_hash] = session.session_id
            self._refresh_index[new_refresh_hash] = session.session_id

    def revoke_session(self, session: SessionRecord, reason: str) -> None:
        """吊销整个会话。

        刻意保留当前凭据索引：凭据本身仍可被识别，但会因 revoked 标记被拒绝，
        从而给出稳定、可归因的结论（SessionRevoked + reason）。
        旧轮换凭据仍留在墓碑索引中，用于重放归因。
        """
        with self._lock:
            session.revoked = True
            session.revoke_reason = reason

    def active_session_count(self) -> int:
        with self._lock:
            return sum(1 for s in self._sessions.values() if not s.revoked)

    # ---- 登录失败计数 / 锁定（账号级） ----
    def get_fail_count(self, username: str) -> int:
        with self._lock:
            return self._fail_counts.get(username, 0)

    def increment_fail_count(self, username: str) -> int:
        with self._lock:
            count = self._fail_counts.get(username, 0) + 1
            self._fail_counts[username] = count
            return count

    def reset_failures(self, username: str) -> None:
        with self._lock:
            self._fail_counts.pop(username, None)
            self._locked_until.pop(username, None)

    def set_locked_until(self, username: str, until: float) -> None:
        with self._lock:
            self._locked_until[username] = until

    def get_locked_until(self, username: str) -> float:
        with self._lock:
            return self._locked_until.get(username, 0.0)
