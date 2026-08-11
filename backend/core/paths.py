import sys
import os
from pathlib import Path

def get_base_dir() -> Path:
    """
    Determines the base directory of the application.
    Handles both development (running via uvicorn) and production (PyInstaller executable).
    """
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        return Path(sys._MEIPASS)
    else:
        # Running in development mode
        # This file is at backend/core/paths.py, so parent.parent = backend/
        return Path(__file__).resolve().parent.parent

BASE_DIR = get_base_dir()

def get_data_dir() -> Path:
    """Data must be stored next to the .exe in production, NOT inside the read-only _MEIPASS."""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent / "data"
    else:
        return BASE_DIR / "data"

DATA_DIR = get_data_dir()
RAW_DIR = DATA_DIR / "raw"
BACKUP_DIR = DATA_DIR / "backups"
DB_PATH = DATA_DIR / "error_panel.db"

# Ensure directories exist dynamically
RAW_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
