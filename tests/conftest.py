"""测试夹具：隔离的 Store/应用与 TestClient。

所有测试在本地内存中运行，无外部服务、无真实凭据。
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app.app_factory import create_app
from app.config import AuthConfig
from app.models_roles import Role
from app.store import Store
from app.auth_service import AuthService
from app.seed import DEMO_USERS
from app.security import hash_password
from app.models import User


@pytest.fixture
def config() -> AuthConfig:
    # 测试用较小阈值，便于触发锁定；TTL 保持默认较长
    return AuthConfig(
        access_token_ttl_seconds=900,
        refresh_token_ttl_seconds=3600,
        max_failed_attempts=3,
        lockout_seconds=10,
        pbkdf2_iterations=1000,
    )


@pytest.fixture
def store(config: AuthConfig) -> Store:
    s = Store()
    for username, (password, roles) in DEMO_USERS.items():
        s.add_user(User(username, hash_password(password, config), roles))
    return s


@pytest.fixture
def service(store: Store, config: AuthConfig) -> AuthService:
    return AuthService(store, config)


@pytest.fixture
def client(store: Store, config: AuthConfig) -> TestClient:
    app = create_app(config, with_seed=False)
    app.state.store = store
    app.state.auth_service = AuthService(store, config)
    return TestClient(app)


@pytest.fixture
def caplog_info(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO, logger="auth")
    return caplog


def login_tokens(client: TestClient, username: str, password: str) -> dict[str, str]:
    """便捷：登录并返回令牌字段。"""
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()
