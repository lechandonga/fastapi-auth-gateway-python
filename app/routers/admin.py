"""管理入口：调整用户角色/权限，演示权限变更的确定生效语义。

生效语义（在 README 中同步说明）：
  - 角色/权限调整本身立即落库；
  - 已签发的访问凭据携带签发时的权限快照，在其过期前仍按旧快照判定；
  - 客户端用刷新凭据轮换或重新登录后，才获得新权限；
  - 若需要“立即逐人生效”，可调用会话撤销（整族失效）。
"""

import logging

from fastapi import APIRouter, Depends

from app.access_control import AccessRule
from app.dependencies import get_store, require_access
from app.errors import NotFoundError
from app.models import Principal, Roles
from app.schemas import RoleUpdateRequest
from app.storage import InMemoryStore

logger = logging.getLogger("auth.router.admin")

router = APIRouter(prefix="/admin", tags=["admin"])

_VALID_ROLES = {role.value for role in Roles}


@router.put("/users/{username}/roles")
def update_roles(
    username: str,
    body: RoleUpdateRequest,
    principal: Principal = Depends(
        require_access(AccessRule(
            require_all_permissions=frozenset({"manage"})))),
    store: InMemoryStore = Depends(get_store),
) -> dict:
    user = store.get_user(username)
    if user is None:
        # 已认证且具备管理权限后，目标用户不存在才返回 404
        raise NotFoundError("目标用户不存在", reason="user_not_found")

    invalid = sorted(set(body.roles) - _VALID_ROLES)
    if invalid:
        from app.errors import GatewayError
        raise GatewayError(f"未知角色: {invalid}", reason="unknown_role")

    old_roles = sorted(user.roles)
    user.roles = sorted(set(body.roles))
    logger.info(
        "roles.updated operator=%s target=%s old=%s new=%s "
        "effective_on=next_refresh_or_login",
        principal.username, username, old_roles, user.roles)
    return {
        "username": username,
        "old_roles": old_roles,
        "new_roles": user.roles,
        "effective": "next_refresh_or_login",
    }
