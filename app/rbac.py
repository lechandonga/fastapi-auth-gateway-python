"""统一的角色/权限判定逻辑，供依赖层、服务层复用。

权限调整语义：每次请求都对当前 User.roles 做实时判定（live evaluation），
因此管理员调整角色后，用户下一次携带仍有效的访问凭据请求即生效，
无需等待凭据过期；签发的凭据本身不携带权限快照。
"""

from __future__ import annotations

import logging

from .models import User
from .models_roles import Permission, Role

logger = logging.getLogger("auth.rbac")

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(
        {Permission.DOCS_READ, Permission.DOCS_WRITE, Permission.ADMIN_PANEL}
    ),
    Role.EDITOR: frozenset({Permission.DOCS_READ, Permission.DOCS_WRITE}),
    Role.VIEWER: frozenset({Permission.DOCS_READ}),
}


def permissions_for_roles(roles: frozenset[Role]) -> frozenset[Permission]:
    result: set[Permission] = set()
    for role in roles:
        result.update(ROLE_PERMISSIONS.get(role, frozenset()))
    return frozenset(result)


def user_has_permission(user: User, permission: Permission) -> bool:
    granted = permission in permissions_for_roles(user.roles)
    logger.info(
        "权限判定: username=%s roles=%s required=%s granted=%s",
        user.username,
        sorted(r.value for r in user.roles),
        permission.value,
        granted,
    )
    return granted
