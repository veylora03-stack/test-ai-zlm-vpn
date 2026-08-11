import sqlite3
from contextlib import contextmanager
from .paths import DB_PATH
from .logger import logger

def get_connection():
    try:
        # Timeout increased to 30s to prevent 'database is locked' errors
        conn = sqlite3.connect(str(DB_PATH), timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        
        # Enable WAL mode for concurrent reads/writes (Crucial for background sync)
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA foreign_keys=ON;')
        conn.execute('PRAGMA synchronous=NORMAL;')
        conn.execute('PRAGMA cache_size=-64000;') # 64MB cache
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to SQLite database: {e}")
        raise

@contextmanager
def get_db():
    conn = get_connection()
    try:
        yield conn
    except Exception as e:
        logger.error(f"Database operation failed: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()
