"""
Mini Vault — server entry point.

Run with:
    uv run python server.py
  or:
    uv run uvicorn src.api.app:app --reload --host 0.0.0.0 --port 8000
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "src.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=False,   # set True for development hot-reload
        log_level="info",
    )
