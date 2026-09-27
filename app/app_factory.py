"""FastAPI 应用工厂：注册路由与统一异常归一化处理器。

任何底层异常都不会直接透出：AuthError 按 code/status 归一化输出，
未预期异常统一归类为 internal_error。
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .auth_service import AuthService
from .config import DEFAULT_CONFIG, AuthConfig
from .errors import AuthError, InternalAuthError
from .routes_auth import router as auth_router
from .routes_resources import router as resource_router
from .seed import build_store

logger = logging.getLogger("auth.gateway")


def create_app(config: AuthConfig = DEFAULT_CONFIG, *, with_seed: bool = True) -> FastAPI:
    app = FastAPI(title="本地认证与权限网关", version="0.1.0")

    store = build_store(config) if with_seed else None
    if store is None:
        from .store import Store

        store = Store()
    app.state.auth_service = AuthService(store, config)
    app.state.store = store
    app.state.config = config

    app.include_router(auth_router)
    app.include_router(resource_router)

    @app.exception_handler(AuthError)
    async def handle_auth_error(request: Request, exc: AuthError) -> JSONResponse:
        logger.warning(
            "归一化领域错误: path=%s code=%s reason=%s status=%s",
            request.url.path,
            exc.code,
            exc.reason,
            exc.http_status,
        )
        headers = {}
        from .errors import AccountLocked

        if isinstance(exc, AccountLocked):
            headers["Retry-After"] = str(exc.retry_after_seconds)
        return JSONResponse(status_code=exc.http_status, content=exc.to_dict(), headers=headers)

    @app.exception_handler(RequestValidationError)
    async def handle_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # 请求体格式问题归一化为可区分类型，不透出 pydantic 原始堆栈
        logger.info("请求参数校验失败: path=%s", request.url.path)
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "reason": "validation_error",
                "message": "请求参数不合法",
            },
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # 兜底：底层库异常绝不直接透出
        logger.exception("未预期异常: path=%s type=%s", request.url.path, type(exc).__name__)
        internal = InternalAuthError()
        return JSONResponse(status_code=internal.http_status, content=internal.to_dict())

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app
