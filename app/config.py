"""认证网关配置。

所有可调参数集中在此处，测试中可构造不同的 AuthConfig 覆盖默认值。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthConfig:
    # 访问凭据存活秒数
    access_token_ttl_seconds: int = 900
    # 刷新凭据存活秒数
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 7
    # 触发账号锁定的连续失败次数（达到该值即锁定）
    max_failed_attempts: int = 5
    # 锁定时长秒数
    lockout_seconds: int = 300
    # PBKDF2 迭代次数
    pbkdf2_iterations: int = 260_000
    # 随机令牌字节数（hex 后翻倍）
    token_bytes: int = 32


DEFAULT_CONFIG = AuthConfig()
