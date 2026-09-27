"""认证主流程、刷新轮换与重放检测。

每个用例都通过 logger 打印关键输入（用户名/凭据前缀/失败次数）
与判定依据（reason/状态码），满足“原因可区分”的验证要求。
"""

import logging

import pytest
from fastapi.testclient import TestClient

from app.bootstrap import create_app
from app.config import Settings

logger = logging.getLogger("test.auth_flow")


@pytest.fixture()
def client() -> TestClient:
    # 测试用短锁定窗口，避免每个用例等待；失败阈值在需要时用环境隔离
    settings = Settings(login_max_failures=3, login_lock_seconds=60)
    return TestClient(create_app(settings))


def _login(client: TestClient, username: str, password: str):
    logger.info("INPUT login username=%s password_len=%s", username, len(password))
    resp = client.post("/auth/login",
                       json={"username": username, "password": password})
    logger.info("DECIDE login status=%s body_keys=%s",
                resp.status_code, list(resp.json().keys())
                if resp.status_code == 200 else resp.json().get("reason"))
    return resp


def test_login_success_issues_token_pair(client: TestClient) -> None:
    resp = _login(client, "alice", "alice12345")
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"] and body["refresh_token"]
    assert body["token_type"] == "Bearer"
    assert body["access_expires_in"] == 900
    assert body["session_id"] and body["family_id"]

    me = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["username"] == "alice"


def test_bad_password_is_distinguishable_error(client: TestClient) -> None:
    resp = _login(client, "alice", "wrong-password")
    assert resp.status_code == 401
    body = resp.json()
    # 对外措辞统一，内部 reason 可区分 bad_password / unknown_username
    assert body["error"] == "invalid_credentials"
    assert body["reason"] == "bad_password"
    assert "用户名或口令错误" in body["message"]


def test_unknown_username_same_external_shape_but_distinct_reason(
        client: TestClient) -> None:
    resp = _login(client, "ghost", "whatever1")
    assert resp.status_code == 401
    body = resp.json()
    assert body["error"] == "invalid_credentials"
    assert body["reason"] == "unknown_username"


def test_refresh_rotates_and_old_token_fails_once(client: TestClient) -> None:
    tokens = _login(client, "alice", "alice12345").json()
    old_refresh = tokens["refresh_token"]

    r1 = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert r1.status_code == 200, r1.text
    new_pair = r1.json()
    assert new_pair["refresh_token"] != old_refresh
    assert new_pair["family_id"] == tokens["family_id"]  # 同属一个凭据族

    # 旧刷新凭据再次使用 => 重放：401 + 可区分 reason
    r2 = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    logger.info("DECIDE replay status=%s reason=%s",
                r2.status_code, r2.json().get("reason"))
    assert r2.status_code == 401
    assert r2.json()["error"] == "refresh_replay"
    assert r2.json()["reason"] == "refresh_token_reused"

    # 重放导致整个会话族失效：轮换出来的新凭据同样不可用
    r3 = client.post("/auth/refresh",
                     json={"refresh_token": new_pair["refresh_token"]})
    assert r3.status_code == 401
    assert r3.json()["error"] == "refresh_replay"
    assert r3.json()["reason"] == "family_revoked_by_replay"

    # 旧访问凭据也即时失效（会话撤销即时生效，不同于权限快照语义）
    me = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {new_pair['access_token']}"})
    assert me.status_code == 401
    assert me.json()["reason"] == "family_revoked_by_replay"


def test_unknown_refresh_token_is_not_classified_as_replay(
        client: TestClient) -> None:
    resp = client.post("/auth/refresh",
                       json={"refresh_token": "never-issued-token-xyz"})
    assert resp.status_code == 401
    body = resp.json()
    assert body["error"] == "token_invalid"
    assert body["reason"] == "refresh_token_unknown"


def test_malformed_and_missing_authorization_are_401(client: TestClient) -> None:
    assert client.get("/auth/me").status_code == 401
    assert client.get(
        "/auth/me", headers={"Authorization": "Basic abc"}).status_code == 401
    assert client.get(
        "/auth/me", headers={"Authorization": "Bearer"}).status_code == 401
    assert client.get(
        "/auth/me",
        headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401


def test_logout_revokes_session_immediately(client: TestClient) -> None:
    tokens = _login(client, "alice", "alice12345").json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.post("/auth/logout", headers=headers).status_code == 204
    # 登出后访问凭据立即被拒，刷新凭据也失效
    assert client.get("/auth/me", headers=headers).status_code == 401
    r = client.post("/auth/refresh",
                    json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401
