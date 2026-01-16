import sqlite3
import zlib
import json
from datetime import datetime, timedelta
from contextlib import contextmanager
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class Cache:
    def __init__(self, db_path: str, ttl_hours: int = 24):
        self.db_path = db_path
        self.ttl_hours = ttl_hours

    def _get_connection(self):
        """Create a direct connection to avoid circular import"""
        return sqlite3.connect(self.db_path)

    def get_cached_response(self, url: str):
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT content, expires_at FROM http_cache WHERE url = ?",
                    (url,)
                )
                row = cursor.fetchone()

                if row:
                    content, expires_at = row
                    expires_dt = datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S')

                    if expires_dt > datetime.now():
                        try:
                            decompressed = zlib.decompress(content).decode('utf-8')
                            logger.debug(f"Cache hit for {url}")
                            return decompressed
                        except:
                            logger.warning(f"Failed to decompress cache for {url}")
                    else:
                        cursor.execute("DELETE FROM http_cache WHERE url = ?", (url,))
                        conn.commit()

        except Exception as e:
            logger.error(f"Error getting cache for {url}: {e}")

        return None

    def cache_response(self, url: str, content: str, headers: dict, status_code: int):
        try:
            expires_at = (datetime.now() + timedelta(hours=self.ttl_hours)).strftime('%Y-%m-%d %H:%M:%S')
            compressed_content = zlib.compress(content.encode('utf-8'))
            headers_json = json.dumps(headers)

            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO http_cache
                    (url, content, headers, status_code, fetched_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    url,
                    compressed_content,
                    headers_json,
                    status_code,
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    expires_at
                ))
                conn.commit()

            logger.debug(f"Cached response for {url}")

        except Exception as e:
            logger.error(f"Error caching response for {url}: {e}")

    def clear_expired(self):
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM http_cache WHERE expires_at < ?",
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),)
                )
                deleted = cursor.rowcount
                conn.commit()

                if deleted > 0:
                    logger.info(f"Cleared {deleted} expired cache entries")

        except Exception as e:
            logger.error(f"Error clearing expired cache: {e}")
