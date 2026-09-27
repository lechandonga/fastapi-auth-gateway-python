"""错误归一化映射测试。

- 底层库（hashlib/hmac/secrets）异常不外泄，统一归类为 internal_error
- pydantic 请求体错误归一化为 invalid_request
- 各类 AuthError 都有稳定的 code/status
- 访问凭据过期在 HTTP 层可区分
"""

from __future__ import annotations

import time

import pytest

from app import security
from app.config import AuthConfig
from app.errors import (
    AccessTokenExpired,
    AuthError,
    ForbiddenError,
    InternalAuthError,
    NotFoundError,
    RefreshTokenReplayed,
)
from app.security import token_fingerprint


def test_library_exception_is_normalized(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("hashlib exploded")

    monkeypatch.setattr(security.hashlib, "pbkdf2_hmac", boom)
    with pytest.raises(InternalAuthError) as ei:
        security.hash_password("whatever", AuthConfig())
    # 对外错误不带底层信息
    assert "hashlib" not in ei.value.message
    assert ei.value.http_status == 500
    assert ei.value.to_dict()["error"] == "internal_error"


def test_verify_password_bad_format_returns_false():
    assert security.verify_password("x", "not-a-valid-hash", AuthConfig()) is False


def test_all_errors_carry_stable_shape():
    cases = [
        (AccessTokenExpired(), 401, "access_token_expired"),
        (ForbiddenError(), 403, "forbidden"),
        (NotFoundError(), 404, "not_found"),
        (RefreshTokenReplayed(), 401, "refresh_token_replayed"),
        (InternalAuthError(), 500, "internal_error"),
    ]
    for exc, status, code in cases:
        assert isinstance(exc, AuthError)
        assert exc.http_status == status
        payload = exc.to_dict()
        assert set(payload) >= {"error", "reason", "message"}
        assert payload["error"] == code


def test_invalid_request_body_is_normalized(client):
    r = client.post("/auth/login", json={"username": "only-name"})
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_request"
    # 不包含 pydantic 原始堆栈
    assert "Traceback" not in r.text


def test_access_token_expiry_is_distinguishable_http(client, store):
    tokens = client.post(
        "/auth/login", json={"username": "viewer", "password": "viewer-pass"}
    ).json()
    fp = token_fingerprint(tokens["access_token"])
    session = store.find_session_by_access(fp)
    session.access_expires_at = time.time() - 1

    r = client.get(
        "/resources/public-doc",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 401
    assert r.json()["error"] == "access_token_expired"
    assert r.json()["reason"] == "ttl_expired"


def test_wrong_scheme_treated_as_missing(client):
    r = client.get("/resources/public-doc", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401
    assert r.json()["error"] == "access_token_missing"
