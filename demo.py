"""本地端到端演示：不依赖外部服务，直接调用 AuthService。

运行：uv run python demo.py
展示：登录 -> 访问资源 -> 刷新轮换 -> 重放吊销 -> 权限边界 -> 连续失败锁定。
"""

from __future__ import annotations

from app.config import AuthConfig
from app.errors import AuthError
from app.models_roles import Permission, Role
from app.seed import build_store
from app.auth_service import AuthService
from app.rbac import user_has_permission


def line(title: str) -> None:
    print(f"\n=== {title} ===")


def show(label: str, fn) -> None:
    try:
        result = fn()
        print(f"[{label}] 成功: {result}")
        return result
    except AuthError as exc:
        print(f"[{label}] 拒绝: status={exc.http_status} error={exc.code} reason={exc.reason}")
        return None


def main() -> None:
    config = AuthConfig(max_failed_attempts=3, lockout_seconds=10, pbkdf2_iterations=1000)
    store = build_store(config)
    auth = AuthService(store, config)

    line("1. 登录签发一对凭据")
    pair = show("viewer 登录", lambda: auth.login("viewer", "viewer-pass"))
    assert pair

    line("2. 访问凭据校验 + 统一 RBAC 判定")
    user, _ = show("访问凭据校验", lambda: auth.authenticate_access(pair.access_token))
    print(
        "viewer 对 DOCS_READ / DOCS_WRITE:",
        user_has_permission(user, Permission.DOCS_READ),
        user_has_permission(user, Permission.DOCS_WRITE),
    )

    line("3. 刷新轮换：旧凭据失效，新凭据生效")
    new_pair = show("正常刷新", lambda: auth.refresh(pair.refresh_token))
    show("旧访问凭据", lambda: auth.authenticate_access(pair.access_token))
    show("旧刷新凭据(重放)", lambda: auth.refresh(pair.refresh_token))
    show("新刷新凭据(会话已整体吊销)", lambda: auth.refresh(new_pair.refresh_token))
    show("新访问凭据(会话已整体吊销)", lambda: auth.authenticate_access(new_pair.access_token))

    line("4. 权限边界与实时调整（editor 临时提权）")
    editor_pair = show("editor 登录", lambda: auth.login("editor", "editor-pass"))
    editor, _ = auth.authenticate_access(editor_pair.access_token)
    print("提权前 ADMIN_PANEL:", user_has_permission(editor, Permission.ADMIN_PANEL))
    store.set_roles("editor", frozenset({Role.EDITOR, Role.ADMIN}))
    print("提权后 ADMIN_PANEL（同一凭据，立即生效）:",
          user_has_permission(editor, Permission.ADMIN_PANEL))

    line("5. 连续失败 -> 账号级锁定（不影响其他账号）")
    for i in range(1, config.max_failed_attempts + 1):
        show(f"第{i}次错误登录", lambda: auth.login("viewer", "wrong-password"))
    show("锁定期间正确密码也被拒", lambda: auth.login("viewer", "viewer-pass"))
    show("其他账号 editor 仍可登录", lambda: auth.login("editor", "editor-pass"))


if __name__ == "__main__":
    main()
