"""认证路由：/auth/login、/auth/refresh、/auth/logout。"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from pydantic import BaseModel

from .deps import get_service

logger = logging.getLogger("auth.routes")

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/login")
def login(body: LoginRequest, request: Request) -> dict:
    logger.info("收到登录请求: username=%s", body.username)
    service = get_service(request)
    pair = service.login(body.username, body.password)
    return {
        "access_token": pair.access_token,
        "refresh_token": pair.refresh_token,
        "token_type": pair.token_type,
        "expires_in": pair.expires_in,
        "refresh_expires_in": pair.refresh_expires_in,
    }


@router.post("/refresh")
def refresh(body: RefreshRequest, request: Request) -> dict:
    logger.info(
        "收到刷新请求: refresh_token_prefix=%s", body.refresh_token[:8] if body.refresh_token else ""
    )
    service = get_service(request)
    pair = service.refresh(body.refresh_token)
    return {
        "access_token": pair.access_token,
        "refresh_token": pair.refresh_token,
        "token_type": pair.token_type,
        "expires_in": pair.expires_in,
        "refresh_expires_in": pair.refresh_expires_in,
    }


@router.post("/logout")
def logout(body: RefreshRequest, request: Request) -> dict:
    logger.info(
        "收到登出请求: refresh_token_prefix=%s", body.refresh_token[:8] if body.refresh_token else ""
    )
    service = get_service(request)
    service.logout(body.refresh_token)
    return {"status": "logged_out"}
