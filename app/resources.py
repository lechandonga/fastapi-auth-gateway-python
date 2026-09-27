"""受保护资源注册表：资源 -> 所需权限。"""

from __future__ import annotations

from dataclasses import dataclass

from .models_roles import Permission


@dataclass(frozen=True)
class Resource:
    key: str
    required_permission: Permission
    content: str


RESOURCES: dict[str, Resource] = {
    "public-doc": Resource("public-doc", Permission.DOCS_READ, "公开文档正文"),
    "draft-doc": Resource("draft-doc", Permission.DOCS_WRITE, "草稿编辑区正文"),
    "admin-panel": Resource("admin-panel", Permission.ADMIN_PANEL, "管理面板数据"),
}


def get_resource(key: str) -> Resource | None:
    return RESOURCES.get(key)
