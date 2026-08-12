"""
ERROR-PANEL Launcher for PyInstaller
This launcher imports the FastAPI application as a proper package
and runs it with uvicorn.
"""

from backend.app.main import app

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
    )