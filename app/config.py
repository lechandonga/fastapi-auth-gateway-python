"""配置项：密钥、凭据生命周期、连续失败限制等，均可通过环境变量覆盖。"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    jwt_secret: str = "local-dev-secret-change-me-32bytes-minimum!!"
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 900                     # 访问凭据有效期：15 分钟
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 7       # 刷新凭据有效期：7 天
    login_max_failures: int = 5                             # 触发锁定的连续失败次数
    login_lock_seconds: int = 300                           # 锁定时长：5 分钟
    issuer: str = "local-auth-gateway"

    @staticmethod
    def from_env() -> "Settings":
        """从环境变量构造配置；未设置的项使用默认值（本地可直接运行）。"""
        def int_env(name: str, default: int) -> int:
            raw = os.environ.get(name)
            return int(raw) if raw is not None and raw != "" else default

        return Settings(
            jwt_secret=os.environ.get("AUTH_JWT_SECRET", Settings.jwt_secret),
            jwt_algorithm=os.environ.get("AUTH_JWT_ALGORITHM", Settings.jwt_algorithm),
            access_token_ttl_seconds=int_env(
                "AUTH_ACCESS_TTL", Settings.access_token_ttl_seconds),
            refresh_token_ttl_seconds=int_env(
                "AUTH_REFRESH_TTL", Settings.refresh_token_ttl_seconds),
            login_max_failures=int_env(
                "AUTH_LOGIN_MAX_FAILURES", Settings.login_max_failures),
            login_lock_seconds=int_env(
                "AUTH_LOGIN_LOCK_SECONDS", Settings.login_lock_seconds),
            issuer=os.environ.get("AUTH_ISSUER", Settings.issuer),
        )


def get_settings() -> Settings:
    return Settings.from_env()
