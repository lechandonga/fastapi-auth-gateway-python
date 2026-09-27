"""并发场景：同一刷新凭据被并发使用时状态必须一致。"""

import logging
import threading
from collections import Counter

import pytest
from fastapi.testclient import TestClient

from app.bootstrap import create_app
from app.config import Settings

logger = logging.getLogger("test.concurrency")


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app(Settings(login_max_failures=3,
                                         login_lock_seconds=60)))


def test_concurrent_refresh_exactly_one_wins(client: TestClient) -> None:
    pair = client.post(
        "/auth/login", json={"username": "alice", "password": "alice12345"}
    ).json()
    refresh_token = pair["refresh_token"]
    logger.info("INPUT concurrent refresh workers=%s token_prefix=%s",
                16, refresh_token[:8])

    barrier = threading.Barrier(16)
    results: Counter[str] = Counter()
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()  # 尽量让所有线程同时发起
        resp = client.post("/auth/refresh",
                           json={"refresh_token": refresh_token})
        with lock:
            results[resp.status_code] += 1
            logger.info(
                "DECIDE worker status=%s reason=%s",
                resp.status_code,
                resp.json().get("reason"))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    logger.info("SUMMARY status_counts=%s", dict(results))
    assert results[200] == 1, "同一刷新凭据必须恰好成功一次"
    assert results[401] == 15, "其余请求必须全部被识别为重放"

    # 重放请求在撤族前已执行：赢家拿到的新凭据也在被撤销的族内，
    # 再用旧 token 仍是明确的重放错误。
    again = client.post("/auth/refresh",
                        json={"refresh_token": refresh_token})
    assert again.status_code == 401
    assert again.json()["error"] == "refresh_replay"


def test_concurrent_failed_logins_lock_state_consistent() -> None:
    """服务层并发失败登录：计数不丢更新，阈值处必然锁定且账号隔离。"""
    from app.auth_service import AuthService
    from app.models import User
    from app.security import hash_password
    from app.storage import InMemoryStore
    from app.errors import AccountLockedError

    settings = Settings(login_max_failures=5, login_lock_seconds=60)
    store = InMemoryStore()
    store.save_user(User("bob", hash_password("correct-pw"), ["user"], []))
    service = AuthService(store, settings)

    outcomes: Counter[str] = Counter()
    barrier = threading.Barrier(10)
    lock = threading.Lock()

    def bad_login() -> None:
        barrier.wait()
        try:
            service.login("bob", "WRONG")
        except AccountLockedError:
            with lock:
                outcomes["locked"] += 1
        except Exception as exc:  # noqa: BLE001
            with lock:
                outcomes[type(exc).__name__] += 1

    threads = [threading.Thread(target=bad_login) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    record = store.failure_record("bob")
    logger.info(
        "INPUT 10 concurrent bad logins; DECIDE failures=%s locked_until_set=%s "
        "outcomes=%s",
        record.consecutive_failures, record.locked_until is not None,
        dict(outcomes))
    # 计数在单个临界区内累加，绝不丢更新；阈值(5)处触发锁定后，
    # 之后的请求在“计数之前”就被锁定短路（计数停在阈值，不继续累加）。
    assert record.consecutive_failures == 5
    assert record.locked_until is not None
    assert outcomes["InvalidCredentialsError"] == 5
    assert outcomes["locked"] == 5

    locked, remaining = store.is_locked("bob")
    assert locked and remaining > 0

    # 其他账号完全不受影响
    store.save_user(User("carol", hash_password("correct-pw"), ["user"], []))
    issued = service.login("carol", "correct-pw")
    assert issued.session_id
    logger.info("DECIDE other-account carol login=ok (not affected by bob lock)")
