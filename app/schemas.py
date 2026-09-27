"""HTTP 请求/响应模型。"""

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    access_expires_in: int
    refresh_expires_in: int
    session_id: str
    family_id: str


class ErrorResponse(BaseModel):
    error: str
    reason: str
    message: str


class RoleUpdateRequest(BaseModel):
    roles: list[str]
