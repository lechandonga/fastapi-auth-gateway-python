"""便捷启动入口：python main.py"""

import uvicorn

from app.app_factory import create_app

app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
