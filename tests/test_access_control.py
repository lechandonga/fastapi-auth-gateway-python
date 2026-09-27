"""权限边界：未认证/无权限/资源不存在 三类结论严格可区分；
以及权限调整后旧访问凭据“快照稳定、刷新后生效”的确定语义。
"""

import logging

import pytest
from fastapi.testclient import TestClient

from app.bootstrap import create_app
from app.config import Settings

logger = logging.getLogger("test.access")


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app(Settings(login_max_failures=3,
                                         login_lock_seconds=60)))


def _bearer(client: TestClient, username: str, password: str) -> dict:
    resp = client.post("/auth/login",
                       json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def test_unauthenticated_is_401(client: TestClient) -> None:
    logger.info("INPUT GET /resources/public-doc without token")
    resp = client.get("/resources/public-doc")
    logger.info("DECIDE status=%s reason=%s", resp.status_code,
                resp.json().get("reason"))
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthenticated"


def test_authenticated_can_read_public_doc(client: TestClient) -> None:
    headers = _bearer(client, "alice", "alice12345")
    resp = client.get("/resources/public-doc", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["resource_id"] == "public-doc"


def test_missing_resource_is_404_not_403(client: TestClient) -> None:
    # 已认证用户访问不存在资源：必须是 404，而不是被权限吞成 403
    headers = _bearer(client, "alice", "alice12345")
    resp = client.get("/resources/no-such-thing", headers=headers)
    logger.info("DECIDE missing-resource status=%s reason=%s",
                resp.status_code, resp.json().get("reason"))
    assert resp.status_code == 404
    assert resp.json()["error"] == "not_found"


def test_forbidden_role_is_403(client: TestClient) -> None:
    # alice 是普通 user，admin-secret 需要 admin 角色；资源存在 => 403
    headers = _bearer(client, "alice", "alice12345")
    resp = client.get("/resources/admin-secret", headers=headers)
    logger.info("DECIDE admin-secret as alice status=%s reason=%s held=%s",
                resp.status_code, resp.json().get("reason"), "user")
    assert resp.status_code == 403
    assert resp.json()["error"] == "permission_denied"
    assert resp.json()["reason"] == "insufficient_permission"


def test_forbidden_permission_is_403_and_auditor_passes(client: TestClient) -> None:
    # audit-log 需要 audit 权限
    alice = _bearer(client, "alice", "alice12345")
    resp = client.get("/resources/audit-log", headers=alice)
    assert resp.status_code == 403

    audrey = _bearer(client, "audrey", "audit12345")
    resp = client.get("/resources/audit-log", headers=audrey)
    assert resp.status_code == 200


def test_admin_can_access_admin_secret(client: TestClient) -> None:
    headers = _bearer(client, "admin", "admin12345")
    assert client.get("/resources/admin-secret",
                      headers=headers).status_code == 200


def test_three_states_have_distinct_status_codes(client: TestClient) -> None:
    """同一资源入口下 401/403/404 必须是三个不同状态码与 error 码。"""
    no_token = client.get("/resources/admin-secret")
    alice = _bearer(client, "alice", "alice12345")
    forbidden = client.get("/resources/admin-secret", headers=alice)
    missing = client.get("/resources/ghost-resource", headers=alice)

    codes = {
        "unauth": (no_token.status_code, no_token.json()["error"]),
        "forbid": (forbidden.status_code, forbidden.json()["error"]),
        "missing": (missing.status_code, missing.json()["error"]),
    }
    logger.info("DECIDE state-matrix=%s", codes)
    assert codes == {
        "unauth": (401, "unauthenticated"),
        "forbid": (403, "permission_denied"),
        "missing": (404, "not_found"),
    }


def test_permission_change_effective_semantics(client: TestClient) -> None:
    """角色调整：旧访问凭据在过期前仍按快照生效；刷新后拿到新权限。"""
    admin = _bearer(client, "admin", "admin12345")

    # alice 登录拿到仅含 user 角色快照的访问凭据
    login = client.post(
        "/auth/login", json={"username": "alice", "password": "alice12345"}
    ).json()
    alice_headers = {"Authorization": f"Bearer {login['access_token']}"}

    # 管理员把 alice 提升为 admin
    r = client.put("/admin/users/alice/roles",
                   json={"roles": ["user", "admin"]}, headers=admin)
    assert r.status_code == 200
    assert r.json()["effective"] == "next_refresh_or_login"

    # 旧访问凭据仍按旧快照 => 依旧 403（语义确定、稳定，不会半途中生效）
    stale = client.get("/resources/admin-secret", headers=alice_headers)
    logger.info("DECIDE after-promotion stale-token status=%s reason=%s",
                stale.status_code, stale.json().get("reason"))
    assert stale.status_code == 403

    # 用刷新凭据轮换 => 新访问凭据携带新角色 => 200
    refreshed = client.post(
        "/auth/refresh", json={"refresh_token": login["refresh_token"]}).json()
    new_headers = {"Authorization": f"Bearer {refreshed['access_token']}"}
    ok = client.get("/resources/admin-secret", headers=new_headers)
    logger.info("DECIDE after-promotion refreshed-token status=%s", ok.status_code)
    assert ok.status_code == 200
    me = client.get("/auth/me", headers=new_headers).json()
    assert "admin" in me["roles"]


def test_admin_endpoint_requires_manage_permission(client: TestClient) -> None:
    alice = _bearer(client, "alice", "alice12345")
    resp = client.put("/admin/users/alice/roles",
                      json={"roles": ["user"]}, headers=alice)
    assert resp.status_code == 403
