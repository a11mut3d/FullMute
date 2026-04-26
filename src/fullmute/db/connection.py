import sqlite3
import threading
from contextlib import contextmanager
from fullmute.utils.logger import setup_logger

logger = setup_logger()

_thread_local = threading.local()

_connection_count = 0
_connection_lock = threading.Lock()


def get_basic_db_connection(db_path: str):
    global _connection_count
    
    conn = sqlite3.connect(db_path)
    
    with _connection_lock:
        _connection_count += 1
        logger.debug(f"Database connection opened: {_connection_count} active")
    
    return conn


@contextmanager
def get_basic_db_context(db_path: str):
    global _connection_count
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    with _connection_lock:
        _connection_count += 1
    
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
        
        with _connection_lock:
            _connection_count -= 1
            logger.debug(f"Database connection closed: {_connection_count} active")


def get_active_connection_count() -> int:
    with _connection_lock:
        return _connection_count
