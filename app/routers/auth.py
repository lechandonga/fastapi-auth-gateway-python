"""认证入口：登录、刷新、登出、查看当前身份。"""

import logging

from fastapi import APIRouter, Depends

from app.dependencies import get_auth_service, require_principal
from app.auth_service import AuthService
from app.models import Principal
from app.schemas import LoginRequest, RefreshRequest, TokenResponse

logger = logging.getLogger("auth.router.auth")

router = APIRouter(prefix="/auth", tags=["auth"])


def _to_response(issued) -> TokenResponse:
    return TokenResponse(
        access_token=issued.access_token,
        refresh_token=issued.refresh_token,
        access_expires_in=issued.access_expires_in,
        refresh_expires_in=issued.refresh_expires_in,
        session_id=issued.session_id,
        family_id=issued.family_id,
    )


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest,
          service: AuthService = Depends(get_auth_service)) -> TokenResponse:
    logger.info("http.login username=%s", body.username)
    return _to_response(service.login(body.username, body.password))


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest,
            service: AuthService = Depends(get_auth_service)) -> TokenResponse:
    # 重放/过期/未知凭据的区分由 service 抛出的错误类型与 reason 表达，
    # 经 handlers 归一化为不同的可解释响应。
    logger.info("http.refresh token_prefix=%s", body.refresh_token[:8])
    return _to_response(service.refresh(body.refresh_token))


@router.post("/logout", status_code=204)
def logout(principal: Principal = Depends(require_principal),
           service: AuthService = Depends(get_auth_service)) -> None:
    logger.info("http.logout user=%s session_id=%s",
                principal.username, principal.session_id)
    service.revoke_session(principal.session_id, reason="logout")


@router.get("/me")
def me(principal: Principal = Depends(require_principal)) -> dict:
    return {
        "username": principal.username,
        "session_id": principal.session_id,
        "family_id": principal.family_id,
        "roles": sorted(principal.roles),
        "permissions": sorted(principal.permissions),
    }
