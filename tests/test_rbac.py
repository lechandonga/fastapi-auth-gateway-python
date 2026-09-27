"""权限边界与 401/403/404 区分、权限调整生效语义测试。"""

from __future__ import annotations

from app.models_roles import Role
from app.rbac import permissions_for_roles
from app.models_roles import Permission


def _auth(client, tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_role_permission_matrix():
    assert Permission.DOCS_READ in permissions_for_roles(frozenset({Role.VIEWER}))
    assert Permission.DOCS_WRITE not in permissions_for_roles(frozenset({Role.VIEWER}))
    editor = permissions_for_roles(frozenset({Role.EDITOR}))
    assert Permission.DOCS_WRITE in editor
    assert Permission.ADMIN_PANEL not in editor
    admin = permissions_for_roles(frozenset({Role.ADMIN}))
    assert Permission.ADMIN_PANEL in admin


def test_unauthenticated_is_401(client):
    r = client.get("/resources/public-doc")
    assert r.status_code == 401
    assert r.json()["error"] == "access_token_missing"

    r = client.get("/resources/public-doc", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401
    assert r.json()["error"] == "access_token_invalid"


def test_forbidden_vs_notfound_are_distinct(client):
    viewer = client.post(
        "/auth/login", json={"username": "viewer", "password": "viewer-pass"}
    ).json()

    # 存在但无权 -> 403
    r = client.get("/resources/draft-doc", headers=_auth(client, viewer))
    assert r.status_code == 403
    assert r.json()["error"] == "forbidden"
    assert r.json()["reason"] == "missing_permission:docs:write"

    # 根本不存在 -> 404（即使已认证）
    r = client.get("/resources/missing", headers=_auth(client, viewer))
    assert r.status_code == 404
    assert r.json()["error"] == "not_found"

    # admin-panel 仅管理员 -> 403
    r = client.get("/resources/admin-panel", headers=_auth(client, viewer))
    assert r.status_code == 403


def test_admin_can_access_all(client):
    admin = client.post(
        "/auth/login", json={"username": "admin", "password": "admin-pass"}
    ).json()
    for key in ("public-doc", "draft-doc", "admin-panel"):
        r = client.get(f"/resources/{key}", headers=_auth(client, admin))
        assert r.status_code == 200, key


def test_permission_change_takes_effect_immediately(client, store):
    """权限调整语义：实时判定。同一个仍有效的访问凭据，
    在角色被提升/降级后，下一次请求即生效，无需重新登录。"""
    editor = client.post(
        "/auth/login", json={"username": "editor", "password": "editor-pass"}
    ).json()
    headers = _auth(client, editor)

    # 提升前无权访问管理面板
    assert client.get("/resources/admin-panel", headers=headers).status_code == 403

    # 管理员实时提升角色（同一凭据不重新签发）
    store.set_roles("editor", frozenset({Role.EDITOR, Role.ADMIN}))
    r = client.get("/resources/admin-panel", headers=headers)
    assert r.status_code == 200, r.text

    # 再实时降级，立即失效
    store.set_roles("editor", frozenset({Role.VIEWER}))
    assert client.get("/resources/admin-panel", headers=headers).status_code == 403
    assert client.get("/resources/draft-doc", headers=headers).status_code == 403
    assert client.get("/resources/public-doc", headers=headers).status_code == 200
