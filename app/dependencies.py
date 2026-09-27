"""FastAPI 依赖：从应用状态取服务、从请求提取并校验凭据、统一鉴权。"""

import logging
from collections.abc import Callable

from fastapi import Request

from app.access_control import AccessRule, has_access
from app.auth_service import AuthService
from app.config import Settings
from app.errors import (
    AuthenticationError,
    NotFoundError,
    PermissionDeniedError,
)
from app.models import Principal
from app.storage import InMemoryStore

logger = logging.getLogger("auth.dependencies")


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_store(request: Request) -> InMemoryStore:
    return request.app.state.store


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def require_principal(request: Request) -> Principal:
    """解析 Authorization: Bearer 并认证，失败统一为 app.errors 的类型。

    缺头/格式错 => unauthenticated（reason=missing_credentials/malformed）；
    底层 JWT 异常已在 security 层归一化，此处不会透传任何库异常。
    """
    header = request.headers.get("Authorization") or request.headers.get(
        "authorization")
    if not header:
        raise AuthenticationError("缺少认证凭据", reason="missing_credentials")

    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise AuthenticationError("认证凭据格式错误", reason="malformed_credentials")

    service: AuthService = request.app.state.auth_service
    return service.authenticate_access_token(parts[1].strip())


def require_access(
    rule: AccessRule,
    resource_exists: Callable[[str], bool] | None = None,
    resource_param: str = "id",
) -> Callable[..., Principal]:
    """生成路由依赖，严格按 认证 -> 存在性 -> 权限 的统一顺序判定。"""

    def dependency(request: Request) -> Principal:
        # 1) 认证：未认证一律 401
        principal = require_principal(request)

        # 2) 资源存在性：不存在一律 404（与权限解耦，便于对外解释）
        if resource_exists is not None:
            resource_id = str(request.path_params.get(resource_param, ""))
            if not resource_exists(resource_id):
                logger.info(
                    "access.denied user=%s resource=%s reason=not_found",
                    principal.username, resource_id)
                raise NotFoundError("资源不存在", reason="resource_not_found")

        # 3) 权限判定：所有入口复用 has_access 这一份逻辑
        if not has_access(principal, rule):
            raise PermissionDeniedError(
                "权限不足", reason="insufficient_permission")
        return principal

    return dependency
