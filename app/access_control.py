"""统一的访问判定逻辑，供 HTTP 依赖与单元测试复用。

判定顺序固定，保证结论可解释、跨入口一致：
  1) 认证（未认证 => 401 unauthenticated / token_invalid / session_revoked）
  2) 资源是否存在（不存在 => 404 not_found；放在权限检查之前，
     因此不会因为“看不见某资源”而暴露资源是否存在之外的权限信息，
     且三类错误状态码严格可区分）
  3) 权限（不足 => 403 permission_denied）
通过 => 返回 Principal。
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass

from app.models import Principal

logger = logging.getLogger("auth.access")


@dataclass(frozen=True)
class AccessRule:
    """一条接口访问规则。

    - require_any_role: 命中任一角色即可；None 表示不限制角色；
    - require_all_permissions: 必须同时具备全部权限；None 表示不要求。
    """
    require_any_role: frozenset[str] | None = None
    require_all_permissions: frozenset[str] | None = None


def has_access(principal: Principal, rule: AccessRule) -> bool:
    """纯函数：判定身份是否满足规则，所有入口共用这一份逻辑。"""
    if rule.require_any_role is not None:
        if not any(role in principal.roles for role in rule.require_any_role):
            logger.info(
                "access.denied user=%s reason=missing_role required_any=%s held=%s",
                principal.username, sorted(rule.require_any_role),
                sorted(principal.roles))
            return False

    if rule.require_all_permissions is not None:
        missing = rule.require_all_permissions - principal.permissions
        if missing:
            logger.info(
                "access.denied user=%s reason=missing_permission missing=%s held=%s",
                principal.username, sorted(missing), sorted(principal.permissions))
            return False

    logger.info("access.allowed user=%s roles=%s permissions=%s",
                principal.username, sorted(principal.roles),
                sorted(principal.permissions))
    return True


# 资源存在性判定：输入资源 id，返回是否存在。
ResourceExists = Callable[[str], bool]
