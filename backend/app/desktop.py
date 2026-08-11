"""ERROR-PANEL — Desktop launcher entry point.

Starts uvicorn programmatically on 127.0.0.1:8000
and opens the browser to it.
"""

import os
import sys
import threading
import webbrowser


def main():
    """Start the ERROR-PANEL server and open browser."""
    import uvicorn

    host = "127.0.0.1"
    port = 8000

    # Open browser after a short delay (headless-safe)
    skip_browser = os.environ.get("ERROR_PANEL_NO_BROWSER", "").lower() in ("1", "true", "yes")
    if not skip_browser:
        def _open_browser():
            try:
                webbrowser.open(f"http://{host}:{port}")
            except Exception:
                pass  # headless environment
        timer = threading.Timer(1.5, _open_browser)
        timer.daemon = True
        timer.start()

    uvicorn.run(
        "backend.app.main:app",
        host=host,
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
