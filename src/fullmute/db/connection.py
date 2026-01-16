import sqlite3
import threading
from contextlib import contextmanager

_thread_local = threading.local()

def get_basic_db_connection(db_path: str):
    """Basic database connection function to avoid circular imports"""
    return sqlite3.connect(db_path)

@contextmanager
def get_basic_db_context(db_path: str):
    """Basic database context manager to avoid circular imports"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
