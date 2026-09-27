"""初始化演示用户与资源（仅内存数据，无真实凭据/外部服务）。

演示账号均为虚构弱密码，仅用于本地运行与测试。
"""

from __future__ import annotations

import logging

from .config import DEFAULT_CONFIG, AuthConfig
from .models import User
from .models_roles import Role
from .resources import RESOURCES
from .security import hash_password
from .store import Store

logger = logging.getLogger("auth.seed")

DEMO_USERS: dict[str, tuple[str, frozenset[Role]]] = {
    "admin": ("admin-pass", frozenset({Role.ADMIN})),
    "editor": ("editor-pass", frozenset({Role.EDITOR})),
    "viewer": ("viewer-pass", frozenset({Role.VIEWER})),
}


def build_store(config: AuthConfig = DEFAULT_CONFIG) -> Store:
    store = Store()
    for username, (password, roles) in DEMO_USERS.items():
        store.add_user(User(username, hash_password(password, config), roles))
    logger.info(
        "已写入演示用户: users=%s 资源数=%s", sorted(DEMO_USERS), len(RESOURCES)
    )
    return store
