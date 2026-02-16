import logging
import sqlite3
import threading
from pathlib import Path
from contextlib import contextmanager
from fullmute.db.schema import SCHEMA

logger = logging.getLogger('fullmute')

_thread_local = threading.local()

def init_db(db_path: str):
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)

    # Проверяем, существует ли таблица domains и столбец final_url
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='domains';")
    table_exists = cursor.fetchone() is not None

    # Создаем или обновляем схему
    conn.executescript(SCHEMA)

    # Если таблица existed, добавляем недостающие столбцы
    if table_exists:
        _update_schema_if_needed(conn)

    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {db_path}")

def _update_schema_if_needed(conn):
    """Обновляет схему базы данных, если она устарела"""
    cursor = conn.cursor()

    # Проверяем, существует ли столбец final_url
    cursor.execute("PRAGMA table_info(domains)")
    columns = [column[1] for column in cursor.fetchall()]

    if 'final_url' not in columns:
        try:
            cursor.execute("ALTER TABLE domains ADD COLUMN final_url TEXT")
            logger.info("Added final_url column to domains table")
        except sqlite3.Error as e:
            logger.warning(f"Could not add final_url column: {e}")

    # Здесь можно добавить другие проверки для будущих обновлений схемы

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
