"""角色与权限枚举。"""

from __future__ import annotations

from enum import Enum


class Permission(str, Enum):
    DOCS_READ = "docs:read"
    DOCS_WRITE = "docs:write"
    ADMIN_PANEL = "admin:panel"


class Role(str, Enum):
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"
