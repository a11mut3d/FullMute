import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional

from fullmute.utils.logger import setup_logger

logger = setup_logger()


class PersistentCache:
    def __init__(self, db_path: Optional[str], namespace: str):
        self.db_path = str(db_path) if db_path else None
        self.namespace = namespace

    def get(self, key: str) -> Any:
        if not self.db_path:
            return None
        try:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT payload, expires_at
                    FROM enrichment_cache
                    WHERE namespace = ? AND cache_key = ?
                    """,
                    (self.namespace, key),
                ).fetchone()
                if not row:
                    return None
                if row[1] <= time.time():
                    conn.execute(
                        """
                        DELETE FROM enrichment_cache
                        WHERE namespace = ? AND cache_key = ?
                        """,
                        (self.namespace, key),
                    )
                    return None
                return json.loads(row[0])
        except (OSError, sqlite3.Error, json.JSONDecodeError, TypeError) as exc:
            logger.warning(
                "Could not read persistent %s cache: %s",
                self.namespace,
                exc,
            )
            return None

    def set(self, key: str, value: Any, ttl: int) -> None:
        if not self.db_path or ttl <= 0:
            return
        try:
            payload = json.dumps(value, ensure_ascii=False)
            now = time.time()
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO enrichment_cache
                        (namespace, cache_key, payload, cached_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(namespace, cache_key) DO UPDATE SET
                        payload = excluded.payload,
                        cached_at = excluded.cached_at,
                        expires_at = excluded.expires_at
                    """,
                    (self.namespace, key, payload, now, now + ttl),
                )
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            logger.warning(
                "Could not write persistent %s cache: %s",
                self.namespace,
                exc,
            )

    @contextmanager
    def _connect(self):
        path = Path(self.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS enrichment_cache (
                    namespace TEXT NOT NULL,
                    cache_key TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    cached_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (namespace, cache_key)
                )
                """
            )
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
