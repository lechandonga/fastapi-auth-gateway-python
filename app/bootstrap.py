"""应用装配：创建存储/服务、灌入演示用户、注册路由与异常处理。"""

import logging

from fastapi import FastAPI

from app.auth_service import AuthService
from app.config import Settings, get_settings
from app.handlers import register_exception_handlers
from app.models import User
from app.routers import admin, auth, resources
from app.security import hash_password
from app.storage import InMemoryStore

logger = logging.getLogger("auth.bootstrap")


def seed_users(store: InMemoryStore) -> None:
    """写入本地演示账号（无真实凭据，弱口令仅用于本地测试）。

    权限模型：
      admin   角色 admin   -> 权限 read/write/manage
      alice   角色 user    -> 权限 read
      audrey  角色 auditor -> 权限 read/audit
    """
    demo_users = [
        User(
            username="admin",
            password_hash=hash_password("admin12345"),
            roles=["admin"],
            permissions=["read", "write", "manage"],
        ),
        User(
            username="alice",
            password_hash=hash_password("alice12345"),
            roles=["user"],
            permissions=["read"],
        ),
        User(
            username="audrey",
            password_hash=hash_password("audit12345"),
            roles=["auditor"],
            permissions=["read", "audit"],
        ),
    ]
    for user in demo_users:
        store.save_user(user)
    logger.info("seed.loaded users=%s", [u.username for u in demo_users])


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    store = InMemoryStore()
    seed_users(store)
    auth_service = AuthService(store, settings)

    app = FastAPI(title="Local Auth Gateway", version="0.1.0")
    app.state.settings = settings
    app.state.store = store
    app.state.auth_service = auth_service

    register_exception_handlers(app)
    app.include_router(auth.router)
    app.include_router(resources.router)
    app.include_router(admin.router)

    @app.get("/", tags=["health"])
    def read_root() -> dict:
        return {"service": "local-auth-gateway", "status": "ok"}

    logger.info(
        "app.ready max_failures=%s lock_seconds=%ss access_ttl=%ss refresh_ttl=%ss",
        settings.login_max_failures, settings.login_lock_seconds,
        settings.access_token_ttl_seconds, settings.refresh_token_ttl_seconds)
    return app
