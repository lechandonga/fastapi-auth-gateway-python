"""FastAPI 依赖：统一的认证 + 鉴权入口，判定逻辑全部复用服务层/RBAC。"""

from __future__ import annotations

import logging

from fastapi import Request

from .auth_service import AuthService
from .errors import ForbiddenError
from .models import User
from .models_roles import Permission
from .rbac import user_has_permission

logger = logging.getLogger("auth.deps")

_BEARER_PREFIX = "Bearer "


def get_service(request: Request) -> AuthService:
    """从应用状态获取认证服务（由 app_factory 注入）。"""
    service: AuthService = getattr(request.app.state, "auth_service")
    return service


def get_bearer_token(request: Request) -> str | None:
    """从 Authorization 头解析 Bearer 凭据；头缺失/方案不符返回 None。"""
    header = request.headers.get("Authorization")
    if not header:
        return None
    if not header.startswith(_BEARER_PREFIX):
        # 方案错误：按“无有效凭据”处理
        logger.info("Authorization 头方案非 Bearer，视为未携带凭据")
        return None
    token = header[len(_BEARER_PREFIX) :].strip()
    return token or None


def current_user(request: Request) -> User:
    """统一认证入口：任何入口都经过同一套归一化错误。"""
    service = get_service(request)
    token = get_bearer_token(request)
    user, _session = service.authenticate_access(token)
    return user


def require_permission(permission: Permission):
    """生成“要求某权限”的路由依赖；认证失败 401，权限不足 403。"""

    def _dependency(request: Request) -> User:
        user = current_user(request)
        if not user_has_permission(user, permission):
            logger.warning(
                "授权拒绝: username=%s 需要权限=%s", user.username, permission.value
            )
            raise ForbiddenError(
                f"用户 {user.username} 缺少权限 {permission.value}",
                reason=f"missing_permission:{permission.value}",
            )
        return user

    return _dependency
