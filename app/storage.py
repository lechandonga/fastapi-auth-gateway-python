"""线程安全的进程内本地存储，模拟会话/凭据/失败计数状态。

- 每个公开方法内部持锁；service 层的“读-判-写”复合流程
  通过可重入的 store.lock 包裹，子方法再次获取同一把锁不会死锁。
- 刷新凭据只存哈希；会话族（family_id）用于重放时整链失效。
"""

import logging
import threading
from collections import defaultdict

from app.models import FailureRecord, RefreshTokenRecord, Session, User, now

logger = logging.getLogger("auth.storage")


class InMemoryStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.users: dict[str, User] = {}
        self.sessions: dict[str, Session] = {}
        self.refresh_tokens: dict[str, RefreshTokenRecord] = {}  # key: token_hash
        self.failure_records: dict[str, FailureRecord] = defaultdict(FailureRecord)

    @property
    def lock(self) -> threading.RLock:
        """供 service 层包裹复合原子操作（可重入）。"""
        return self._lock

    # ---- 用户 ----
    def get_user(self, username: str) -> User | None:
        with self._lock:
            return self.users.get(username)

    def save_user(self, user: User) -> None:
        with self._lock:
            self.users[user.username] = user

    # ---- 会话 ----
    def put_session(self, session: Session) -> None:
        with self._lock:
            self.sessions[session.session_id] = session

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self.sessions.get(session_id)

    def revoke_family(self, family_id: str, reason: str) -> int:
        """撤销某个凭据族下的全部会话与刷新凭据，返回受影响会话数。"""
        with self._lock:
            count = 0
            for session in self.sessions.values():
                if session.family_id == family_id and not session.revoked:
                    session.revoked = True
                    session.revoke_reason = reason
                    count += 1
            for record in self.refresh_tokens.values():
                if record.family_id == family_id:
                    record.revoked = True
            logger.info("family.revoked family_id=%s reason=%s sessions=%s",
                        family_id, reason, count)
            return count

    # ---- 刷新凭据 ----
    def put_refresh_token(self, record: RefreshTokenRecord) -> None:
        with self._lock:
            self.refresh_tokens[record.token_hash] = record

    def get_refresh_token(self, token_hash: str) -> RefreshTokenRecord | None:
        with self._lock:
            return self.refresh_tokens.get(token_hash)

    # ---- 账号失败计数 / 锁定 ----
    def failure_record(self, username: str) -> FailureRecord:
        with self._lock:
            return self.failure_records[username]

    def reset_failures(self, username: str) -> None:
        with self._lock:
            self.failure_records[username] = FailureRecord()

    def register_failure(self, username: str, max_failures: int,
                         lock_seconds: int) -> FailureRecord:
        """登记一次失败；达到阈值则设置锁定截止时间。返回最新记录。"""
        with self._lock:
            record = self.failure_records[username]
            record.consecutive_failures += 1
            if record.consecutive_failures >= max_failures:
                record.locked_until = now() + lock_seconds
                logger.warning(
                    "account.locked username=%s failures=%s locked_until=%.0f",
                    username, record.consecutive_failures, record.locked_until)
            return record

    def is_locked(self, username: str, at: float | None = None) -> tuple[bool, int]:
        """返回 (是否锁定, 剩余秒数)。锁定已过期时自动清零，不影响计数语义。"""
        with self._lock:
            record = self.failure_records[username]
            if record.locked_until is None:
                return False, 0
            current = now() if at is None else at
            remaining = record.locked_until - current
            if remaining <= 0:
                record.locked_until = None
                return False, 0
            return True, int(remaining) + 1
