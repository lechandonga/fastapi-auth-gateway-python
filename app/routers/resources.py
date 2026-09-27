"""受保护资源入口，用于演示统一鉴权与 401/403/404 的明确区分。

资源权限：
  public-doc  仅需认证（任意已登录身份）
  admin-secret 需要 admin 角色
  audit-log   需要 audit 权限
"""

import logging

from fastapi import APIRouter, Depends

from app.access_control import AccessRule
from app.dependencies import require_access
from app.models import Principal

logger = logging.getLogger("auth.router.resources")

router = APIRouter(prefix="/resources", tags=["resources"])

# 资源 id -> (内容, 访问规则)
RESOURCE_REGISTRY: dict[str, tuple[str, AccessRule]] = {
    "public-doc": (
        "公开资源说明：任何已登录用户均可读取",
        AccessRule(),
    ),
    "admin-secret": (
        "仅管理员可见的秘密",
        AccessRule(require_any_role=frozenset({"admin"})),
    ),
    "audit-log": (
        "仅具备 audit 权限的身份可读的日志",
        AccessRule(require_all_permissions=frozenset({"audit"})),
    ),
}


def _resource_exists(resource_id: str) -> bool:
    return resource_id in RESOURCE_REGISTRY


@router.get("/{resource_id}")
def get_resource(
    resource_id: str,
    principal: Principal = Depends(
        require_access(AccessRule(), resource_exists=_resource_exists,
                       resource_param="resource_id")),
) -> dict:
    # require_access 已完成：认证(401) -> 存在性(404) -> 基础规则；
    # 资源级规则在此统一复用同一份 has_access 做二次判定（不另造逻辑）。
    from app.access_control import has_access
    from app.errors import PermissionDeniedError

    _, rule = RESOURCE_REGISTRY[resource_id]
    if not has_access(principal, rule):
        raise PermissionDeniedError(
            "权限不足", reason="insufficient_permission")
    logger.info(
        "resource.served user=%s resource=%s roles=%s permissions=%s",
        principal.username, resource_id,
        sorted(principal.roles), sorted(principal.permissions))
    return {"resource_id": resource_id, "data": RESOURCE_REGISTRY[resource_id][0]}
