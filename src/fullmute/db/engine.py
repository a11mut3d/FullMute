import sqlite3
import threading
from pathlib import Path
from contextlib import contextmanager
from fullmute.db.schema import SCHEMA
from fullmute.utils.logger import setup_logger

logger = setup_logger()

_thread_local = threading.local()

_connection_count = 0
_connection_lock = threading.Lock()


def init_db(db_path: str):
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)

    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='domains';")
    table_exists = cursor.fetchone() is not None

    conn.executescript(SCHEMA)

    if table_exists:
        _update_schema_if_needed(conn)

    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {db_path}")


def _update_schema_if_needed(conn):
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(domains)")
    columns = [column[1] for column in cursor.fetchall()]

    if 'final_url' not in columns:
        try:
            cursor.execute("ALTER TABLE domains ADD COLUMN final_url TEXT")
            logger.info("Added final_url column to domains table")
        except sqlite3.Error as e:
            logger.warning(f"Could not add final_url column: {e}")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='default_credentials'")
    if not cursor.fetchone():
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS default_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    login_url TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT,
                    description TEXT,
                    detection_reason TEXT,
                    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (domain_id) REFERENCES domains (id)
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_default_creds_domain ON default_credentials(domain_id)")
            logger.info("Added default_credentials table")
        except sqlite3.Error as e:
            logger.warning(f"Could not add default_credentials table: {e}")



@contextmanager
def get_db_connection(db_path: str):
    global _connection_count
    
    if not hasattr(_thread_local, 'connections'):
        _thread_local.connections = {}

    if db_path not in _thread_local.connections:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        
        with _connection_lock:
            _connection_count += 1
            logger.debug(f"DB connection opened: {_connection_count} active")
        
        _thread_local.connections[db_path] = conn
    else:
        conn = _thread_local.connections[db_path]

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
        _thread_local.connections.pop(db_path, None)
        
        with _connection_lock:
            _connection_count -= 1
            logger.debug(f"DB connection closed: {_connection_count} active")


def close_all_connections():
    global _connection_count
    
    if hasattr(_thread_local, 'connections'):
        for db_path, conn in list(_thread_local.connections.items()):
            try:
                conn.close()
                logger.debug(f"Closed connection to {db_path}")
            except Exception as e:
                logger.error(f"Error closing connection: {e}")
        
        _thread_local.connections = {}
        
        with _connection_lock:
            _connection_count = 0
        
        logger.info("All database connections closed")


def get_active_connection_count() -> int:
    with _connection_lock:
        return _connection_count
