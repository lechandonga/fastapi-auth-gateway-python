"""资源路由：展示 401/403/404 的可区分判定。

判定顺序（有意为之，见 README）：
  1) 认证：未携带/无效/过期凭据 -> 401
  2) 资源存在性：资源 key 不存在 -> 404
  3) 授权：权限不足 -> 403
对“存在但无权”的资源返回 403，对“根本不存在”的资源返回 404。
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request

from .deps import current_user
from .errors import ForbiddenError, NotFoundError
from .rbac import user_has_permission
from .resources import get_resource
from .models_roles import Role

logger = logging.getLogger("auth.routes")

router = APIRouter(prefix="/resources", tags=["resources"])


@router.get("/{key}")
def read_resource(key: str, request: Request) -> dict:
    # 1) 认证（未认证先于一切，不泄露资源是否存在）
    user = current_user(request)

    # 2) 存在性
    resource = get_resource(key)
    if resource is None:
        logger.info("资源不存在: key=%s 访问用户=%s", key, user.username)
        raise NotFoundError(f"资源 {key} 不存在", reason="unknown_resource")

    # 3) 授权（统一复用 RBAC 判定）
    if not user_has_permission(user, resource.required_permission):
        logger.warning(
            "资源访问被拒: key=%s username=%s required=%s roles=%s",
            key,
            user.username,
            resource.required_permission.value,
            sorted(r.value for r in user.roles),
        )
        raise ForbiddenError(
            f"无权访问资源 {key}",
            reason=f"missing_permission:{resource.required_permission.value}",
        )

    logger.info("资源访问放行: key=%s username=%s", key, user.username)
    return {"key": resource.key, "content": resource.content, "accessed_by": user.username}
