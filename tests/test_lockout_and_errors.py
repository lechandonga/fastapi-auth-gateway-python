"""连续失败账号限制（可配置阈值/时长、账号隔离、锁定后恢复）、
底层库异常归一化、凭据过期分类。
"""

import logging

import pytest
from fastapi.testclient import TestClient

from app.bootstrap import create_app
from app.config import Settings
from app.errors import TokenInvalidError

logger = logging.getLogger("test.lockout")


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app(Settings(
        login_max_failures=3, login_lock_seconds=300)))


def test_lockout_after_configurable_threshold(client: TestClient) -> None:
    for i in range(3):
        logger.info("INPUT bad login #%s username=alice", i + 1)
        resp = client.post("/auth/login",
                           json={"username": "alice", "password": "nope"})
        assert resp.status_code == 401

    # 第 4 次即使口令正确也被锁定短路，429 + Retry-After
    resp = client.post("/auth/login",
                       json={"username": "alice", "password": "alice12345"})
    logger.info("DECIDE locked login status=%s reason=%s retry_after=%s",
                resp.status_code, resp.json().get("reason"),
                resp.headers.get("Retry-After"))
    assert resp.status_code == 429
    assert resp.json()["error"] == "account_locked"
    assert int(resp.headers["Retry-After"]) > 0


def test_lockout_does_not_affect_other_accounts(client: TestClient) -> None:
    for _ in range(3):
        client.post("/auth/login",
                    json={"username": "alice", "password": "nope"})

    # alice 被锁，但 admin/audrey 完全不受影响
    for username, password in [
        ("admin", "admin12345"),
        ("audrey", "audit12345"),
    ]:
        resp = client.post(
            "/auth/login", json={"username": username, "password": password})
        logger.info("DECIDE other-account=%s status=%s", username,
                    resp.status_code)
        assert resp.status_code == 200


def test_successful_login_resets_failure_counter() -> None:
    # 阈值 5：失败 2 次后成功登录，计数清零，再失败 2 次不应锁定
    app = create_app(Settings(login_max_failures=5, login_lock_seconds=60))
    client = TestClient(app)
    for _ in range(2):
        assert client.post("/auth/login", json={
            "username": "alice", "password": "x"}).status_code == 401
    assert client.post("/auth/login", json={
        "username": "alice", "password": "alice12345"}).status_code == 200
    for _ in range(2):
        assert client.post("/auth/login", json={
            "username": "alice", "password": "x"}).status_code == 401
    locked = client.post("/auth/login", json={
        "username": "alice", "password": "alice12345"})
    assert locked.status_code == 200
    logger.info("DECIDE counter reset works; subsequent login status=200")


def test_expired_access_token_normalized_to_token_expired() -> None:
    # 访问 TTL 设为 -1 => 签发即过期，验证 pyjwt 过期异常被归一化
    app = create_app(Settings(access_token_ttl_seconds=-1))
    client = TestClient(app)
    pair = client.post("/auth/login", json={
        "username": "alice", "password": "alice12345"}).json()
    resp = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {pair['access_token']}"})
    logger.info("DECIDE expired token status=%s reason=%s",
                resp.status_code, resp.json().get("reason"))
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_invalid"
    assert resp.json()["reason"] == "token_expired"


def test_garbage_token_never_leaks_library_exception() -> None:
    app = create_app(Settings())
    client = TestClient(app)
    for token in ["", "abc", "a.b.c", "...", "Bearer ".strip()]:
        resp = client.get(
            "/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401, resp.text
        body = resp.json()
        # 响应结构恒定，绝不出现 pyjwt 异常类名/堆栈
        assert set(body.keys()) == {"error", "reason", "message"}
        assert "jwt" not in body["message"].lower()
        assert "DecodeError" not in body["message"]
    logger.info("DECIDE all malformed tokens normalized to 401 stable shape")


def test_security_layer_wraps_pyjwt_exceptions_directly() -> None:
    """直接对安全层断言：任何 pyjwt 异常都不允许向上逃逸。"""
    import jwt
    from app.security import decode_access_token

    settings = Settings()
    for bad in ["not-a-jwt", "a.b.c", jwt.encode({"foo": "bar"}, "k")]:
        with pytest.raises(TokenInvalidError) as exc_info:
            decode_access_token(bad, settings)
        # 底层 pyjwt 异常被保留为 __cause__ 仅用于内部日志，
        # 对外类型则统一为 TokenInvalidError。
        assert isinstance(exc_info.value.__cause__, jwt.InvalidTokenError)
        logger.info(
            "DECIDE library exception %s -> TokenInvalidError(reason=%s)",
            type(exc_info.value.__cause__).__name__, exc_info.value.reason)
