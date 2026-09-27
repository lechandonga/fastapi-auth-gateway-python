"""统一错误类型体系。

所有对外错误都继承自 AuthError，携带稳定的 code（机器可读）与
http_status，路由层据此归一化输出，绝不向调用方透出底层库异常。

错误分类：
- 401 未认证（凭据缺失/无效/过期/会话被吊销）
- 403 已认证但无权限
- 404 资源不存在
- 423 账号被锁定
- 500 内部错误（底层细节不外泄）
"""

from __future__ import annotations

from typing import Any


class AuthError(Exception):
    """所有认证/鉴权领域错误的基类。"""

    code: str = "auth_error"
    http_status: int = 400
    default_message: str = "认证错误"

    def __init__(self, message: str | None = None, *, reason: str | None = None) -> None:
        super().__init__(message or self.default_message)
        self.message = message or self.default_message
        # reason 用于进一步区分同一 HTTP 状态码下的不同原因
        self.reason = reason or self.code

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.code, "reason": self.reason, "message": self.message}


# ---- 401 未认证系列 ----
class UnauthenticatedError(AuthError):
    code = "unauthenticated"
    http_status = 401
    default_message = "缺少或无效的访问凭据"


class AccessTokenMissing(UnauthenticatedError):
    code = "access_token_missing"
    default_message = "请求未携带访问凭据"


class AccessTokenExpired(UnauthenticatedError):
    code = "access_token_expired"
    default_message = "访问凭据已过期"


class AccessTokenInvalid(UnauthenticatedError):
    code = "access_token_invalid"
    default_message = "访问凭据无效"


class SessionRevoked(UnauthenticatedError):
    code = "session_revoked"
    default_message = "会话已失效"


class RefreshTokenInvalid(UnauthenticatedError):
    code = "refresh_token_invalid"
    default_message = "刷新凭据无法识别"


class RefreshTokenExpired(UnauthenticatedError):
    code = "refresh_token_expired"
    default_message = "刷新凭据已过期"


class RefreshTokenReplayed(UnauthenticatedError):
    """刷新凭据重放：检测到凭据轮换后的旧/已用凭据，整个会话被吊销。"""

    code = "refresh_token_replayed"
    default_message = "刷新凭据已被使用过，会话因疑似重放已整体失效"


# ---- 403 无权限 ----
class ForbiddenError(AuthError):
    code = "forbidden"
    http_status = 403
    default_message = "无权访问该资源"


# ---- 404 资源不存在 ----
class NotFoundError(AuthError):
    code = "not_found"
    http_status = 404
    default_message = "资源不存在"


# ---- 423 账号锁定 ----
class AccountLocked(AuthError):
    code = "account_locked"
    http_status = 423
    default_message = "账号因连续登录失败已被临时锁定"

    def __init__(
        self,
        message: str | None = None,
        *,
        retry_after_seconds: int = 0,
        reason: str | None = None,
    ) -> None:
        super().__init__(message, reason=reason)
        self.retry_after_seconds = retry_after_seconds

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["retry_after_seconds"] = self.retry_after_seconds
        return data


# ---- 凭据错误（登录失败归一化） ----
class InvalidCredentials(AuthError):
    code = "invalid_credentials"
    http_status = 401
    default_message = "用户名或密码错误"


# ---- 500 内部错误 ----
class InternalAuthError(AuthError):
    code = "internal_error"
    http_status = 500
    default_message = "认证服务内部错误"
