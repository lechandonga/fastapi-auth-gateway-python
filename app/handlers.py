"""异常归一化：GatewayError => 统一 JSON 结构；未捕获异常 => 500 且不透出细节。"""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.errors import AccountLockedError, GatewayError

logger = logging.getLogger("auth.handlers")


def _error_body(error_code: str, reason: str, message: str) -> dict:
    return {"error": error_code, "reason": reason, "message": message}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(GatewayError)
    async def handle_gateway_error(request: Request, exc: GatewayError) -> JSONResponse:
        headers = {}
        if isinstance(exc, AccountLockedError) and exc.retry_after > 0:
            headers["Retry-After"] = str(exc.retry_after)
        logger.info(
            "http.error status=%s code=%s reason=%s path=%s",
            exc.status_code, exc.error_code, exc.reason, request.url.path)
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.error_code, exc.reason, exc.message),
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation(request: Request,
                                exc: RequestValidationError) -> JSONResponse:
        # 请求体结构错误归为一类可区分错误，不回显 pydantic 内部细节。
        logger.info("http.error status=422 reason=validation_error path=%s",
                    request.url.path)
        return JSONResponse(
            status_code=422,
            content=_error_body(
                "validation_error", "validation_error", "请求参数不合法"),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # 兜底：记录完整异常类型用于排查，但对外只给稳定的 error 结构。
        logger.exception(
            "http.error status=500 code=internal_error type=%s path=%s",
            type(exc).__name__, request.url.path)
        return JSONResponse(
            status_code=500,
            content=_error_body("internal_error", "internal_error", "服务内部错误"),
        )
