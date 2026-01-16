import sqlite3
import threading
from pathlib import Path
from contextlib import contextmanager
from fullmute.db.schema import SCHEMA
from fullmute.utils.logger import setup_logger

logger = setup_logger()

_thread_local = threading.local()

def init_db(db_path: str):
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {db_path}")

@contextmanager
def get_db_connection(db_path: str):
    if not hasattr(_thread_local, 'connections'):
        _thread_local.connections = {}

    if db_path not in _thread_local.connections:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        _thread_local.connections[db_path] = conn
    else:
        conn = _thread_local.connections[db_path]

    try:
        yield conn
    finally:
        
        
        pass

def close_all_connections():
    if hasattr(_thread_local, 'connections'):
        for conn in _thread_local.connections.values():
            conn.close()
        _thread_local.connections = {}
