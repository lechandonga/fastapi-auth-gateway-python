"""uvicorn 入口：python -m app.main"""

from __future__ import annotations

import uvicorn

from .app_factory import create_app

app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
