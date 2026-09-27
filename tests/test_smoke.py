"""骨架冒烟测试：验证 app 可装配、根路径可访问。"""


def test_app_imports_and_root() -> None:
    from app.bootstrap import create_app
    from fastapi.testclient import TestClient

    client = TestClient(create_app())
    resp = client.get("/")
    assert resp.status_code == 200
