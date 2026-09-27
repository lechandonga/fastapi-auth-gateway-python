"""领域模型：角色、权限、用户、会话记录。"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum

from .models_roles import Permission, Role


class User:
    __slots__ = ("username", "password_hash", "roles")

    def __init__(self, username: str, password_hash: str, roles: frozenset[Role]) -> None:
        self.username = username
        self.password_hash = password_hash
        self.roles = roles


@dataclass
class SessionRecord:
    """一个登录会话；每次刷新轮换凭据，但 session_id 保持不变。"""

    username: str
    refresh_token_hash: str
    refresh_expires_at: float
    access_token_hash: str
    access_expires_at: float
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.time)
    revoked: bool = False
    revoke_reason: str = ""
    # 历次轮换作废的刷新凭据指纹（tombstone），用于识别重放
    used_refresh_hashes: set[str] = field(default_factory=set)

    def is_refresh_alive(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return not self.revoked and now < self.refresh_expires_at
