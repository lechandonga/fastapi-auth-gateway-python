"""对外可区分的错误类型。所有错误统一继承 GatewayError，不向调用方透出底层库异常。"""


class GatewayError(Exception):
    error_code: str = "gateway_error"
    status_code: int = 400

    def __init__(self, message: str, *, reason: str | None = None):
        super().__init__(message)
        self.message = message
        self.reason = reason or self.error_code


class AuthenticationError(GatewayError):
    """401：未认证或凭据无效。"""
    error_code = "unauthenticated"
    status_code = 401


class InvalidCredentialsError(AuthenticationError):
    """登录失败：用户名或口令错误（对外统一措辞，避免账号枚举）。"""
    error_code = "invalid_credentials"
    status_code = 401


class TokenInvalidError(AuthenticationError):
    """凭据无法解析 / 已过期 / 签名错误等，由底层库异常归一化而来。"""
    error_code = "token_invalid"
    status_code = 401


class SessionRevokedError(AuthenticationError):
    """会话已被撤销（含重放攻击导致的整链失效）。"""
    error_code = "session_revoked"
    status_code = 401


class RefreshReplayError(AuthenticationError):
    """刷新凭据重放：该凭据此前已被使用过，会话已整体失效。"""
    error_code = "refresh_replay"
    status_code = 401


class AccountLockedError(GatewayError):
    """账号因连续失败被临时锁定，附带 Retry-After 语义（剩余秒数）。"""
    error_code = "account_locked"
    status_code = 429

    def __init__(self, message: str, *, reason: str | None = None,
                 retry_after: int = 0):
        super().__init__(message, reason=reason)
        self.retry_after = retry_after


class PermissionDeniedError(GatewayError):
    """403：已认证但权限不足。"""
    error_code = "permission_denied"
    status_code = 403


class NotFoundError(GatewayError):
    """404：资源不存在（与 401/403 明确区分）。"""
    error_code = "not_found"
    status_code = 404
