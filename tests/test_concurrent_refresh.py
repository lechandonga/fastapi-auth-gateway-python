"""并发刷新测试：同一刷新凭据被并发使用时恰好一次成功。

其余请求必须被识别为重放（refresh_token_replayed），
且会话整体被吊销，后续任何凭据都不能再用。
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from app.errors import RefreshTokenReplayed, SessionRevoked
from app.security import token_fingerprint


def test_concurrent_refresh_exactly_one_wins(service, store, caplog_info):
    pair = service.login("editor", "editor-pass")
    shared_refresh = pair.refresh_token

    n = 16
    barrier = threading.Barrier(n)

    def worker() -> dict:
        barrier.wait()  # 尽量让所有线程同时进入临界区
        try:
            new_pair = service.refresh(shared_refresh)
            return {"ok": True, "tokens": new_pair}
        except RefreshTokenReplayed as exc:
            return {"ok": False, "code": exc.code, "reason": exc.reason}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "code": type(exc).__name__, "reason": str(exc)}

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(lambda _: worker(), range(n)))

    successes = [r for r in results if r["ok"]]
    failures = [r for r in results if not r["ok"]]

    assert len(successes) == 1, f"期望恰好 1 次成功，实际 {len(successes)}"
    assert len(failures) == n - 1
    assert all(r["code"] == "refresh_token_replayed" for r in failures)
    assert all(r["reason"] == "refresh_token_replay" for r in failures)

    # 会话必须已被整体吊销
    session = store.find_replay_session(token_fingerprint(shared_refresh))
    assert session.revoked is True

    # 唯一一次成功签发的新凭据也不能再用（会话已吊销），且原因可归因
    winning = successes[0]["tokens"]
    try:
        service.refresh(winning.refresh_token)
        assert False
    except SessionRevoked as exc:
        assert exc.reason == "refresh_token_replay"

    # 日志中必须能看到重放判定依据
    assert any("刷新凭据重放" in rec.message for rec in caplog_info.records)


def test_concurrent_refresh_http(client):
    tok = client.post(
        "/auth/login", json={"username": "editor", "password": "editor-pass"}
    ).json()
    shared = tok["refresh_token"]
    n = 12
    barrier = threading.Barrier(n)

    def worker() -> int:
        barrier.wait()
        r = client.post("/auth/refresh", json={"refresh_token": shared})
        return r.status_code

    with ThreadPoolExecutor(max_workers=n) as pool:
        statuses = list(pool.map(lambda _: worker(), range(n)))

    assert statuses.count(200) == 1
    assert statuses.count(401) == n - 1
