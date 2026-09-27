"""账号级连续失败限制。

以用户名为键：锁定只影响目标账号，不误伤其他账号。
所有读写都在 Store 的同一把锁内完成，保证并发下状态一致。
"""

from __future__ import annotations

import logging
import time

from .config import AuthConfig
from .errors import AccountLocked
from .store import Store

logger = logging.getLogger("auth.ratelimit")


class LoginThrottle:
    def __init__(self, store: Store, config: AuthConfig) -> None:
        self.store = store
        self.config = config

    def _now(self) -> float:
        return time.time()

    def is_locked(self, username: str) -> bool:
        return self.retry_after_seconds(username) > 0

    def retry_after_seconds(self, username: str) -> int:
        """返回剩余锁定秒数；锁已过期则清理并返回 0。"""
        with self.store.lock():
            until = self.store.get_locked_until(username)
            if until <= 0:
                return 0
            remaining = until - self._now()
            if remaining <= 0:
                # 锁定窗口结束：清理锁与计数，重新开始计数
                self.store.reset_failures(username)
                logger.info("账号锁定窗口已结束: username=%s", username)
                return 0
            return int(remaining) + (1 if remaining % 1 else 0)

    def ensure_not_locked(self, username: str) -> None:
        remaining = self.retry_after_seconds(username)
        if remaining > 0:
            logger.warning(
                "登录被拒绝（账号锁定）: username=%s retry_after=%ss", username, remaining
            )
            raise AccountLocked(
                f"账号 {username} 已被临时锁定，请 {remaining} 秒后重试",
                retry_after_seconds=remaining,
                reason="too_many_failures",
            )

    def get_fail_count(self, username: str) -> int:
        with self.store.lock():
            return self.store.get_fail_count(username)

    def register_failure(self, username: str) -> int:
        """记录一次失败；达到阈值则设置锁定并抛出 AccountLocked。

        触发阈值的那一次请求本身也得到 423（而不是普通凭据错误），
        语义确定且并发下恰好由一个线程完成锁定转换。
        """
        with self.store.lock():
            # 注册失败前再次确认不在锁定期（锁定期内的尝试不应延长/重置计数）
            if self.is_locked(username):
                self.ensure_not_locked(username)
            count = self.store.increment_fail_count(username)
            if count >= self.config.max_failed_attempts:
                until = self._now() + self.config.lockout_seconds
                self.store.set_locked_until(username, until)
                logger.warning(
                    "账号触发锁定: username=%s failures=%s lockout=%ss",
                    username,
                    count,
                    self.config.lockout_seconds,
                )
                raise AccountLocked(
                    f"账号 {username} 连续失败 {count} 次，已被临时锁定",
                    retry_after_seconds=self.config.lockout_seconds,
                    reason="too_many_failures",
                )
            logger.info(
                "登录失败计数: username=%s failures=%s/%s",
                username,
                count,
                self.config.max_failed_attempts,
            )
            return count

    def reset(self, username: str) -> None:
        with self.store.lock():
            self.store.reset_failures(username)
        logger.info("登录成功，已重置失败计数: username=%s", username)
