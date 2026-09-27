"""核心数据模型：用户、角色、会话、凭据、登录失败记录。"""

from dataclasses import dataclass, field
import enum
import time


Role = str


class Roles(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"
    AUDITOR = "auditor"


@dataclass
class User:
    username: str
    password_hash: str
    roles: list[Role]
    permissions: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class RefreshTokenRecord:
    """一条已签发的刷新凭据记录（仅存哈希）。"""
    token_hash: str
    session_id: str
    family_id: str
    username: str
    issued_at: float
    expires_at: float
    used: bool = False
    revoked: bool = False


@dataclass
class Session:
    session_id: str
    family_id: str
    username: str
    created_at: float
    revoked: bool = False
    revoke_reason: str | None = None


@dataclass
class IssuedCredentials:
    access_token: str
    refresh_token: str
    access_expires_in: int
    refresh_expires_in: int
    session_id: str
    family_id: str


@dataclass
class FailureRecord:
    consecutive_failures: int = 0
    locked_until: float | None = None


@dataclass(frozen=True)
class Principal:
    """认证通过后得到的调用方身份，权限快照在签发访问凭据时冻结。"""
    username: str
    session_id: str
    family_id: str
    roles: frozenset[str]
    permissions: frozenset[str]


def now() -> float:
    return time.time()
