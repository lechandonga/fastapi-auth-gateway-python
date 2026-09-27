"""刷新凭据轮换与重放检测测试。

覆盖：
- 登录签发一对凭据
- 刷新后旧访问/刷新凭据立即失效，新凭据可用
- 重复/重放旧刷新凭据 => refresh_token_replayed，且整个会话被吊销
- 重放后新轮换出的凭据也失效，原因可归因为 refresh_token_replay
- 无法识别的刷新凭据与过期刷新凭据各自可区分
"""

from __future__ import annotations

import time

from app.errors import (
    RefreshTokenExpired,
    RefreshTokenInvalid,
    RefreshTokenReplayed,
    SessionRevoked,
)
from app.security import token_fingerprint


def test_login_issues_token_pair(service):
    pair = service.login("viewer", "viewer-pass")
    assert pair.access_token
    assert pair.refresh_token
    assert pair.access_token != pair.refresh_token
    assert pair.expires_in == 900


def test_refresh_rotates_and_invalidates_old(service, store):
    pair = service.login("viewer", "viewer-pass")
    old_access, old_refresh = pair.access_token, pair.refresh_token

    new_pair = service.refresh(old_refresh)
    assert new_pair.refresh_token != old_refresh
    assert new_pair.access_token != old_access

    # 旧刷新凭据 -> 重放
    try:
        service.refresh(old_refresh)
        assert False, "应当抛出重放错误"
    except RefreshTokenReplayed as exc:
        assert exc.reason == "refresh_token_replay"

    # 会话被整体吊销
    session = store.find_replay_session(token_fingerprint(old_refresh))
    assert session is not None
    assert session.revoked is True
    assert session.revoke_reason == "refresh_token_replay"

    # 新轮换出的刷新凭据也失效，原因可归因为重放
    try:
        service.refresh(new_pair.refresh_token)
        assert False
    except SessionRevoked as exc:
        assert exc.reason == "refresh_token_replay"

    # 新访问凭据同样被拒绝并归因
    try:
        service.authenticate_access(new_pair.access_token)
        assert False
    except SessionRevoked as exc:
        assert exc.reason == "refresh_token_replay"


def test_replay_unknown_token_is_invalid_not_replay(service):
    try:
        service.refresh("a" * 64)
        assert False
    except RefreshTokenInvalid as exc:
        assert exc.code == "refresh_token_invalid"
        assert exc.reason == "unknown_token"


def test_expired_refresh_token_is_distinguishable(service, store, config):
    pair = service.login("viewer", "viewer-pass")
    fp = token_fingerprint(pair.refresh_token)
    session = store.find_session_by_refresh(fp)
    # 模拟刷新凭据过期
    session.refresh_expires_at = time.time() - 1

    try:
        service.refresh(pair.refresh_token)
        assert False
    except RefreshTokenExpired as exc:
        assert exc.reason == "ttl_expired"


def test_replay_via_http_is_distinguishable(client):
    tok = client.post(
        "/auth/login", json={"username": "viewer", "password": "viewer-pass"}
    ).json()
    client.post("/auth/refresh", json={"refresh_token": tok["refresh_token"]})
    r = client.post("/auth/refresh", json={"refresh_token": tok["refresh_token"]})
    assert r.status_code == 401
    body = r.json()
    assert body["error"] == "refresh_token_replayed"
    assert body["reason"] == "refresh_token_replay"


def test_logout_revokes_session_and_is_idempotent(service, store):
    pair = service.login("viewer", "viewer-pass")
    service.logout(pair.refresh_token)

    try:
        service.authenticate_access(pair.access_token)
        assert False
    except SessionRevoked as exc:
        assert exc.reason == "user_logout"

    # 再次登出同一凭据：幂等，不报错
    service.logout(pair.refresh_token)
