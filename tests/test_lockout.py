"""连续失败限制测试。

- 达到阈值后账号被锁定（423），原因可区分，带 Retry-After
- 锁定期间不得误伤其他账号
- 锁定期内即使密码正确也不放行
- 锁定窗口结束后自动恢复
- 并发失败计数不会出现超计/少计，状态一致
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from app.errors import AccountLocked, InvalidCredentials


def test_lockout_after_threshold(service, store, config, caplog_info):
    for i in range(config.max_failed_attempts - 1):
        try:
            service.login("viewer", "wrong")
        except InvalidCredentials:
            pass
        assert service.throttle.get_fail_count("viewer") == i + 1

    # 第 threshold 次失败 -> 锁定
    try:
        service.login("viewer", "wrong")
        assert False
    except AccountLocked as exc:
        assert exc.reason == "too_many_failures"
        assert exc.retry_after_seconds > 0

    # 锁定期内即使密码正确也被拒
    try:
        service.login("viewer", "viewer-pass")
        assert False
    except AccountLocked:
        pass

    # 日志包含关键判定依据
    assert any("账号触发锁定" in r.message for r in caplog_info.records)


def test_lockout_is_per_account(service):
    # 锁死 viewer
    for _ in range(3):
        try:
            service.login("viewer", "bad")
        except (InvalidCredentials, AccountLocked):
            pass

    # editor 不受影响
    pair = service.login("editor", "editor-pass")
    assert pair.access_token


def test_lockout_http_status_and_retry_after(client, config):
    for _ in range(config.max_failed_attempts):
        client.post("/auth/login", json={"username": "viewer", "password": "bad"})
    r = client.post("/auth/login", json={"username": "viewer", "password": "viewer-pass"})
    assert r.status_code == 423
    body = r.json()
    assert body["error"] == "account_locked"
    assert body["reason"] == "too_many_failures"
    assert int(r.headers["Retry-After"]) > 0

    # 其他账号仍可登录
    assert (
        client.post(
            "/auth/login", json={"username": "editor", "password": "editor-pass"}
        ).status_code
        == 200
    )


def test_lockout_window_expires(service, config, store):
    for _ in range(config.max_failed_attempts):
        try:
            service.login("viewer", "bad")
        except (InvalidCredentials, AccountLocked):
            pass
    assert service.throttle.is_locked("viewer")

    # 把锁定截止时间推到过去，模拟窗口结束
    store.set_locked_until("viewer", time.time() - 1)
    assert not service.throttle.is_locked("viewer")

    # 恢复登录并清零计数
    pair = service.login("viewer", "viewer-pass")
    assert pair.access_token
    assert service.throttle.get_fail_count("viewer") == 0


def test_concurrent_failures_lock_exactly_once(service, store, config):
    n = config.max_failed_attempts
    with ThreadPoolExecutor(max_workers=n) as pool:
        outcomes = list(
            pool.map(
                lambda _: _attempt(service),
                range(n),
            )
        )
    # 恰好有一次调用把账号推入锁定态；其余为普通凭据错误
    locked = [o for o in outcomes if o == "locked"]
    invalid = [o for o in outcomes if o == "invalid"]
    assert len(locked) == 1
    assert len(invalid) == n - 1

    # 状态一致：计数恰好等于阈值，且确实处于锁定
    assert store.get_fail_count("viewer") == config.max_failed_attempts
    assert service.throttle.is_locked("viewer")


def _attempt(service) -> str:
    try:
        service.login("viewer", "bad")
    except AccountLocked:
        return "locked"
    except InvalidCredentials:
        return "invalid"
    return "other"
