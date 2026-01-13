import json
from datetime import datetime
from contextlib import contextmanager
from fullmute.db.engine import get_db_connection
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class DBQueries:
    def __init__(self, db_path: str):
        self.db_path = db_path

    @contextmanager
    def _get_cursor(self):
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                yield cursor
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise e

    def add_domain(self, domain_data: dict):
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT OR REPLACE INTO domains
                    (domain, scanned_at, has_camera, is_alive, response_time, http_status, technologies, sensitive_files)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    domain_data.get('domain'),
                    domain_data.get('scanned_at', datetime.now()),
                    domain_data.get('has_camera', False),
                    domain_data.get('is_alive', True),
                    domain_data.get('response_time'),
                    domain_data.get('http_status'),
                    json.dumps(domain_data.get('technologies', [])),
                    json.dumps(domain_data.get('sensitive_files', []))
                ))
        except Exception as e:
            logger.error(f"Failed to add domain {domain_data.get('domain')}: {e}")

    def add_technology(self, technology_data: dict):
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT OR IGNORE INTO technologies
                    (domain_id, category, name, version, detection_method, confidence, first_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    technology_data.get('domain_id'),
                    technology_data.get('category'),
                    technology_data.get('name'),
                    technology_data.get('version'),
                    technology_data.get('detection_method', 'signature'),
                    technology_data.get('confidence', 100),
                    technology_data.get('first_seen', datetime.now())
                ))
        except Exception as e:
            logger.error(f"Failed to add technology: {e}")

    def add_sensitive_file(self, file_data: dict):
        try:
            with self._get_cursor() as cursor:
                cursor.execute('''
                    INSERT OR IGNORE INTO sensitive_files
                    (domain_id, file_path, file_type, verification_result, content_sample, found_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    file_data.get('domain_id'),
                    file_data.get('file_path'),
                    file_data.get('file_type'),
                    file_data.get('verification_result'),
                    file_data.get('content_sample'),
                    file_data.get('found_at', datetime.now())
                ))
        except Exception as e:
            logger.error(f"Failed to add sensitive file: {e}")

    def get_domain_id(self, domain: str) -> int:
        try:
            with self._get_cursor() as cursor:
                cursor.execute('SELECT id FROM domains WHERE domain = ?', (domain,))
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Failed to get domain ID for {domain}: {e}")
            return None

    def search_domains(self, query: str = None, params: tuple = ()):
        try:
            with self._get_cursor() as cursor:
                sql = 'SELECT * FROM domains'
                if query:
                    sql += f' WHERE {query}'
                cursor.execute(sql, params)
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to search domains: {e}")
            return []

    def fetch_all_domains(self):
        return self.search_domains()
