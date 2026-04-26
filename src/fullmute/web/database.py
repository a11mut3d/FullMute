import sqlite3
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from pathlib import Path
import json
import hashlib
import secrets
import threading
from fullmute.utils.logger import setup_logger

logger = setup_logger()

from fullmute.web.config import config



_local = threading.local()


def get_db_path() -> str:
    db_path = Path(config.database_path)
    if not db_path.is_absolute():
        db_path = Path(__file__).parent.parent.parent.parent / db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return str(db_path)


def get_scanner_db_path() -> str:
    db_path = Path(config.scanner_database)
    if not db_path.is_absolute():
        db_path = Path(__file__).parent.parent.parent.parent / db_path
    return str(db_path)


@contextmanager
def get_db_connection():
    conn = None
    try:
        
        if hasattr(_local, 'connection') and _local.connection is not None:
            conn = _local.connection
        else:
            conn = sqlite3.connect(
                get_db_path(),
                timeout=30.0,  
                isolation_level=None  
            )
            conn.row_factory = sqlite3.Row
            
            
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA cache_size = -64000")  
            conn.execute("PRAGMA temp_store = MEMORY")
            conn.execute("PRAGMA busy_timeout = 30000")  
            conn.execute("PRAGMA foreign_keys = ON")
            
            
            _local.connection = conn
        
        yield conn
        
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        raise
    finally:
        
        
        pass


def get_thread_db_connection():
    if hasattr(_local, 'connection') and _local.connection is not None:
        return _local.connection
    
    conn = sqlite3.connect(
        get_db_path(),
        timeout=30.0,
        isolation_level=None
    )
    conn.row_factory = sqlite3.Row
    
    
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA cache_size = -64000")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA foreign_keys = ON")
    
    _local.connection = conn
    return conn


def close_thread_db_connection():
    if hasattr(_local, 'connection') and _local.connection is not None:
        try:
            _local.connection.close()
        except Exception:
            pass
        finally:
            _local.connection = None


def init_web_db():
    with get_db_connection() as conn:
        conn.executescript("""
            -- Organizations for multi-tenant isolation
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Default organization
            INSERT OR IGNORE INTO organizations (id, name) VALUES (1, 'Default');
            
            -- Users table with API key authentication
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                api_key_hash TEXT NOT NULL,
                api_key_prefix TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'scanner',
                organization_id INTEGER DEFAULT 1,
                expires_at TIMESTAMP,
                grace_period_ends TIMESTAMP,
                expired_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (organization_id) REFERENCES organizations (id)
            );
        """)

        
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'expires_at' not in columns:
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN expires_at TIMESTAMP")
                logger.info("Added expires_at column to users table")
            except sqlite3.Error as e:
                logger.warning(f"Could not add expires_at column: {e}")
        
        
        if 'grace_period_ends' not in columns:
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN grace_period_ends TIMESTAMP")
                logger.info("Added grace_period_ends column to users table")
            except sqlite3.Error as e:
                logger.warning(f"Could not add grace_period_ends column: {e}")
        
        
        if 'expired_at' not in columns:
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN expired_at TIMESTAMP")
                logger.info("Added expired_at column to users table")
            except sqlite3.Error as e:
                logger.warning(f"Could not add expired_at column: {e}")
        
        
        conn.executescript("""
            -- Target groups for organizing domains
            CREATE TABLE IF NOT EXISTS target_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                organization_id INTEGER DEFAULT 1,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (organization_id) REFERENCES organizations (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            );
            
            -- Individual targets (domains)
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                organization_id INTEGER DEFAULT 1,
                group_id INTEGER,
                is_active BOOLEAN DEFAULT 1,
                last_scan_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (organization_id) REFERENCES organizations (id),
                FOREIGN KEY (group_id) REFERENCES target_groups (id),
                FOREIGN KEY (last_scan_id) REFERENCES scans (id),
                UNIQUE(domain, organization_id)
            );
            
            -- Scan configurations
            CREATE TABLE IF NOT EXISTS scan_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                organization_id INTEGER DEFAULT 1,
                scan_type TEXT NOT NULL DEFAULT 'manual',
                schedule_type TEXT,
                schedule_value TEXT,
                target_group_ids TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_run TIMESTAMP,
                next_run TIMESTAMP,
                FOREIGN KEY (organization_id) REFERENCES organizations (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            );
            
            -- Scan results
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER DEFAULT 1,
                config_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                progress INTEGER DEFAULT 0,
                total_targets INTEGER DEFAULT 0,
                completed_targets INTEGER DEFAULT 0,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_scan_number INTEGER DEFAULT 1,
                FOREIGN KEY (organization_id) REFERENCES organizations (id),
                FOREIGN KEY (config_id) REFERENCES scan_configs (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            );
            
            -- Scan target mapping
            CREATE TABLE IF NOT EXISTS scan_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                target_id INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                result_path TEXT,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id),
                FOREIGN KEY (target_id) REFERENCES targets (id)
            );
            
            -- API access log
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                resource TEXT,
                ip_address TEXT,
                user_agent TEXT,
                status_code INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            
            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key_hash);
            CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain);
            CREATE INDEX IF NOT EXISTS idx_targets_group ON targets(group_id);
            CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
            CREATE INDEX IF NOT EXISTS idx_scans_config ON scans(config_id);
            CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(created_by, user_scan_number);
            CREATE INDEX IF NOT EXISTS idx_scan_targets_scan ON scan_targets(scan_id);
            CREATE INDEX IF NOT EXISTS idx_access_log_user ON access_log(user_id);
            CREATE INDEX IF NOT EXISTS idx_access_log_created ON access_log(created_at);
        """)

        
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(scans)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'user_scan_number' not in columns:
            try:
                cursor.execute("ALTER TABLE scans ADD COLUMN user_scan_number INTEGER DEFAULT 1")
                logger.info("Added user_scan_number column to scans table")
                
                
                cursor.execute("SELECT DISTINCT created_by FROM scans")
                users = cursor.fetchall()
                for user in users:
                    user_id = user[0]
                    cursor.execute("""
                        UPDATE scans 
                        SET user_scan_number = (
                            SELECT COUNT(*) + 1 
                            FROM scans s2 
                            WHERE s2.created_by = scans.created_by 
                            AND s2.created_at < scans.created_at
                        ) + 1
                        WHERE created_by = ?
                    """, (user_id,))
                conn.commit()
                logger.info("Updated user_scan_number for existing scans")
            except sqlite3.Error as e:
                logger.warning(f"Could not add user_scan_number column: {e}")

        
        cursor.execute("PRAGMA table_info(access_log)")
        columns = [col[1] for col in cursor.fetchall()]
        if not columns:
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS access_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        action TEXT NOT NULL,
                        resource TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        status_code INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_log_user ON access_log(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_log_created ON access_log(created_at)")
                conn.commit()
                logger.info("Created access_log table")
            except sqlite3.Error as e:
                logger.warning(f"Could not create access_log table: {e}")

        
        cursor.execute("PRAGMA table_info(scan_targets)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'result_path' not in columns:
            try:
                cursor.execute("ALTER TABLE scan_targets ADD COLUMN result_path TEXT")
                logger.info("Added result_path column to scan_targets table")
            except sqlite3.Error as e:
                logger.warning(f"Could not add result_path column: {e}")

        
        conn.executescript("""
            -- User settings for personal NVD API key and proxy settings
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                nvd_api_key TEXT,
                proxy_enabled BOOLEAN DEFAULT 0,
                proxy_list TEXT,
                max_concurrent_scans INTEGER DEFAULT 3,
                port_scan_enabled BOOLEAN DEFAULT 0,
                port_scan_with_cves BOOLEAN DEFAULT 0,
                port_scan_with_exploits BOOLEAN DEFAULT 0,
                test_default_credentials BOOLEAN DEFAULT 1,
                search_exploits BOOLEAN DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );

            CREATE INDEX IF NOT EXISTS idx_user_settings_user ON user_settings(user_id);
        """)

        
        cursor.execute("PRAGMA table_info(targets)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'created_by' not in columns:
            try:
                cursor.execute("ALTER TABLE targets ADD COLUMN created_by INTEGER")
                logger.info("Added created_by column to targets table")
            except sqlite3.Error as e:
                logger.warning(f"Could not add created_by column: {e}")
        
        
        if 'organization_id' not in columns:
            try:
                cursor.execute("ALTER TABLE targets ADD COLUMN organization_id INTEGER DEFAULT 1")
                logger.info("Added organization_id column to targets table")
            except sqlite3.Error as e:
                logger.warning(f"Could not add organization_id column: {e}")

        conn.commit()


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def generate_api_key() -> str:
    """Generate a new API key"""
    return secrets.token_urlsafe(32)


def get_api_key_prefix(api_key: str) -> str:
    return api_key[:8] + "..."


def create_user(username: str, api_key: str, role: str = "viewer") -> Optional[int]:
    with get_db_connection() as conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, api_key_hash, api_key_prefix, role)
                VALUES (?, ?, ?, ?)
            """, (username, hash_api_key(api_key), get_api_key_prefix(api_key), role))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None


def authenticate_user(api_key: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, role, is_active, last_login, expires_at, grace_period_ends, expired_at
            FROM users
            WHERE api_key_hash = ? AND is_active = 1
        """, (hash_api_key(api_key),))
        row = cursor.fetchone()

        if row:
            user_dict = dict(row)
            expires_at = user_dict.get('expires_at')
            grace_period_ends = user_dict.get('grace_period_ends')
            expired_at = user_dict.get('expired_at')
            
            now = datetime.now()
            
            
            if expires_at:
                expires_at_dt = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else expires_at
                
                if now > expires_at_dt:
                    
                    
                    
                    if expired_at:
                        expired_at_dt = datetime.fromisoformat(expired_at) if isinstance(expired_at, str) else expired_at
                        if now > expired_at_dt:
                            
                            logger.info(f"User {user_dict['username']} fully expired, blocking access")
                            return None
                    
                    
                    if grace_period_ends:
                        grace_period_ends_dt = datetime.fromisoformat(grace_period_ends) if isinstance(grace_period_ends, str) else grace_period_ends
                        
                        if now > grace_period_ends_dt:
                            
                            cursor.execute("""
                                UPDATE users SET expired_at = ? WHERE id = ?
                            """, (now.isoformat(), row['id']))
                            conn.commit()
                            logger.info(f"User {user_dict['username']} grace period ended, blocking access")
                            return None
                        else:
                            
                            logger.info(f"User {user_dict['username']} in grace period until {grace_period_ends}")
                            return {
                                'id': row['id'],
                                'username': row['username'],
                                'role': row['role'],
                                'in_grace_period': True,
                                'grace_period_ends': grace_period_ends,
                                'expires_at': expires_at
                            }
                    else:
                        
                        logger.info(f"User {user_dict['username']} expired, no grace period, blocking access")
                        return None
            
            
            conn.execute("""
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            """, (row['id'],))
            conn.commit()

            return {
                'id': row['id'],
                'username': row['username'],
                'role': row['role']
            }
        return None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, api_key_prefix, role, created_at, last_login, is_active
            FROM users WHERE id = ?
        """, (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def list_users(organization_id: int = None) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        if organization_id is None:
            cursor.execute("""
                SELECT id, username, api_key_prefix, role, organization_id, expires_at, created_at, last_login, is_active
                FROM users ORDER BY created_at DESC
            """)
        else:
            cursor.execute("""
                SELECT id, username, api_key_prefix, role, organization_id, expires_at, created_at, last_login, is_active
                FROM users WHERE organization_id = ? ORDER BY created_at DESC
            """, (organization_id,))
        
        return [dict(row) for row in cursor.fetchall()]


def delete_user(user_id: int) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return cursor.rowcount > 0


def update_user_expires(user_id: int, expires_at: str) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET expires_at = ? WHERE id = ?", (expires_at, user_id))
        conn.commit()
        return cursor.rowcount > 0


def regenerate_api_key(user_id: int) -> Optional[str]:
    new_key = generate_api_key()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET api_key_hash = ?, api_key_prefix = ?
            WHERE id = ?
        """, (hash_api_key(new_key), get_api_key_prefix(new_key), user_id))
        conn.commit()
        if cursor.rowcount > 0:
            return new_key
    return None


def add_target_group(name: str, description: str, user_id: int, organization_id: int = 1) -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO target_groups (name, description, organization_id, created_by)
            VALUES (?, ?, ?, ?)
        """, (name, description, organization_id, user_id))
        conn.commit()
        return cursor.lastrowid


def get_target_groups(organization_id: int = None, created_by: int = None) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        if created_by is not None:
            
            cursor.execute("""
                SELECT g.*, COUNT(t.id) as target_count
                FROM target_groups g
                LEFT JOIN targets t ON g.id = t.group_id
                WHERE g.created_by = ?
                GROUP BY g.id
                ORDER BY g.created_at DESC
            """, (created_by,))
        elif organization_id is None:
            
            cursor.execute("""
                SELECT g.*, COUNT(t.id) as target_count
                FROM target_groups g
                LEFT JOIN targets t ON g.id = t.group_id
                GROUP BY g.id
                ORDER BY g.created_at DESC
            """)
        else:
            
            cursor.execute("""
                SELECT g.*, COUNT(t.id) as target_count
                FROM target_groups g
                LEFT JOIN targets t ON g.id = t.group_id
                WHERE g.organization_id = ?
                GROUP BY g.id
                ORDER BY g.created_at DESC
            """, (organization_id,))
        
        return [dict(row) for row in cursor.fetchall()]


def add_target(domain: str, group_id: Optional[int] = None, created_by: int = 1, organization_id: int = 1) -> Optional[int]:
    logger.info(f"add_target: domain={domain}, group_id={group_id}, created_by={created_by}, organization_id={organization_id}")
    with get_db_connection() as conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO targets (domain, group_id, created_by, organization_id, is_active)
                VALUES (?, ?, ?, ?, 1)
            """, (domain, group_id, created_by, organization_id))
            conn.commit()
            logger.info(f"add_target: inserted target with id={cursor.lastrowid}")
            return cursor.lastrowid
        except sqlite3.IntegrityError as e:
            logger.warning(f"add_target: IntegrityError (target may exist): {e}")
            
            cursor.execute("SELECT id FROM targets WHERE domain = ?", (domain,))
            row = cursor.fetchone()
            
            if row:
                cursor.execute("UPDATE targets SET is_active = 1 WHERE id = ?", (row[0],))
                conn.commit()
                logger.info(f"add_target: activated existing target with id={row[0]}")
            return row[0] if row else None


def add_targets_batch(domains: List[str], group_id: Optional[int] = None, created_by: int = 1, organization_id: int = 1) -> int:
    added = 0
    with get_db_connection() as conn:
        cursor = conn.cursor()
        for domain in domains:
            domain = domain.strip()
            if domain:
                try:
                    cursor.execute("""
                        INSERT INTO targets (domain, group_id, created_by, organization_id, is_active)
                        VALUES (?, ?, ?, ?, 1)
                    """, (domain, group_id, created_by, organization_id))
                    added += 1
                except sqlite3.IntegrityError:
                    pass
        conn.commit()
    return added


def get_targets(group_id: Optional[int] = None, search: str = None, organization_id: int = None, created_by: int = None) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        if created_by is not None:
            
            query = """
                SELECT t.*, g.name as group_name,
                       s.status as last_scan_status, s.completed_at as last_scan_date
                FROM targets t
                LEFT JOIN target_groups g ON t.group_id = g.id
                LEFT JOIN scans s ON t.last_scan_id = s.id
                WHERE t.created_by = ? AND t.is_active = 1
            """
            params = [created_by]
        elif organization_id is None:
            
            query = """
                SELECT t.*, g.name as group_name,
                       s.status as last_scan_status, s.completed_at as last_scan_date
                FROM targets t
                LEFT JOIN target_groups g ON t.group_id = g.id
                LEFT JOIN scans s ON t.last_scan_id = s.id
                WHERE t.is_active = 1
            """
            params = []
        else:
            
            query = """
                SELECT t.*, g.name as group_name,
                       s.status as last_scan_status, s.completed_at as last_scan_date
                FROM targets t
                LEFT JOIN target_groups g ON t.group_id = g.id
                LEFT JOIN scans s ON t.last_scan_id = s.id
                WHERE t.organization_id = ? AND t.is_active = 1
            """
            params = [organization_id]

        if group_id:
            query += " AND t.group_id = ?"
            params.append(group_id)

        if search:
            query += " AND t.domain LIKE ?"
            params.append(f"%{search}%")

        query += " ORDER BY t.created_at DESC"

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


def delete_target(target_id: int) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE targets SET is_active = 0 WHERE id = ?
        """, (target_id,))
        conn.commit()
        return cursor.rowcount > 0


def create_scan_config(
    name: str,
    scan_type: str,
    schedule_type: Optional[str],
    schedule_value: Optional[str],
    target_group_ids: List[int],
    description: str = "",
    user_id: int = None
) -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_configs 
            (name, description, scan_type, schedule_type, schedule_value, target_group_ids, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            name, 
            description, 
            scan_type, 
            schedule_type, 
            schedule_value,
            json.dumps(target_group_ids),
            user_id
        ))
        conn.commit()
        return cursor.lastrowid


def get_scan_configs() -> List[Dict[str, Any]]:
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT c.*, u.username as creator_name
                FROM scan_configs c
                LEFT JOIN users u ON c.created_by = u.id
                ORDER BY c.created_at DESC
            """)
            configs = []
            for row in cursor.fetchall():
                config_dict = dict(row)
                config_dict['target_group_ids'] = json.loads(config_dict['target_group_ids'] or '[]')
                configs.append(config_dict)
            return configs
    except sqlite3.OperationalError:
        
        return []


def create_scan(config_id: Optional[int], target_ids: List[int], user_id: int, organization_id: int = 1) -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()

        
        try:
            cursor.execute("PRAGMA table_info(scans)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'user_scan_number' not in columns:
                cursor.execute("ALTER TABLE scans ADD COLUMN user_scan_number INTEGER DEFAULT 1")
                logger.info("Added user_scan_number column to scans table (migration)")
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not add user_scan_number column: {e}")

        
        cursor.execute("""
            SELECT COALESCE(MAX(user_scan_number), 0) + 1
            FROM scans
            WHERE created_by = ?
        """, (user_id,))
        next_user_number = cursor.fetchone()[0]

        
        cursor.execute("""
            INSERT INTO scans (organization_id, config_id, status, total_targets, created_by, user_scan_number)
            VALUES (?, ?, 'pending', ?, ?, ?)
        """, (organization_id, config_id, len(target_ids), user_id, next_user_number))
        scan_id = cursor.lastrowid

        
        for target_id in target_ids:
            
            cursor.execute("""
                SELECT id FROM targets 
                WHERE id = ? AND (created_by = ? OR ? = 1)
            """, (target_id, user_id, 1 if user_id == 1 else 0))  
            if cursor.fetchone():
                cursor.execute("""
                    INSERT INTO scan_targets (scan_id, target_id)
                    VALUES (?, ?)
                """, (scan_id, target_id))
            else:
                logger.warning(f"User {user_id} tried to scan target {target_id} they don't own")

        conn.commit()
        return scan_id


def update_scan_results(scan_id: int, results: List[Dict]):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        for result in results:
            domain = result.get('domain')
            if not domain:
                logger.debug(f"Skipping result without domain for scan {scan_id}")
                continue

            
            
            cursor.execute("""
                SELECT id FROM targets 
                WHERE domain = ? AND created_by = (
                    SELECT created_by FROM scans WHERE id = ?
                )
            """, (domain, scan_id))
            target_row = cursor.fetchone()
            if not target_row:
                logger.warning(f"Target not found for domain {domain} in scan {scan_id}")
                continue

            target_id = target_row[0]

            
            
            technologies = result.get('technologies', [])
            cves = result.get('cves', [])
            sensitive_files = result.get('sensitive_files', [])
            default_credentials = result.get('default_credentials', [])
            exploits = result.get('exploits', {})
            open_ports = result.get('open_ports', [])  

            
            logger.info(f"Saving for {domain}: {len(technologies)} techs, {len(cves)} cves, {len(sensitive_files)} files, {len(default_credentials)} creds, {sum(len(e) for e in exploits.values())} exploits, {len(open_ports)} ports")

            result_data = {
                'technologies': technologies,
                'cves': cves,
                'sensitive_files': sensitive_files,
                'default_credentials': default_credentials,
                'exploits': exploits,
                'status': result.get('status', 'completed'),
                'cameras_count': result.get('cameras_count', 0),
                'exploits_count': result.get('exploits_count', 0),
                'open_ports': open_ports  
            }

            
            cursor.execute("""
                UPDATE scan_targets
                SET status = ?,
                    result_path = ?
                WHERE scan_id = ? AND target_id = ?
            """, (
                result.get('status', 'completed'),
                json.dumps(result_data),
                scan_id,
                target_id
            ))

        conn.commit()
        logger.info(f"Saved results for scan {scan_id}")


def get_scan_results(scan_id: int) -> List[Dict]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT st.*, t.domain
            FROM scan_targets st
            JOIN targets t ON st.target_id = t.id
            WHERE st.scan_id = ?
        """, (scan_id,))

        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            if row_dict.get('result_path'):
                try:
                    result_data = json.loads(row_dict['result_path'])
                    row_dict['technologies'] = result_data.get('technologies', [])
                    row_dict['cves'] = result_data.get('cves', [])
                    row_dict['sensitive_files'] = result_data.get('sensitive_files', [])
                    row_dict['default_credentials'] = result_data.get('default_credentials', [])
                    row_dict['cameras_count'] = result_data.get('cameras_count', 0)
                    row_dict['open_ports'] = result_data.get('open_ports', [])  
                    logger.debug(f"Loaded for {row_dict['domain']}: {len(row_dict['technologies'])} techs, {len(row_dict['cves'])} cves, {len(row_dict.get('open_ports', []))} ports")
                except Exception as e:
                    logger.error(f"Error parsing result_path: {e}")
                    row_dict['technologies'] = []
                    row_dict['cves'] = []
                    row_dict['sensitive_files'] = []
                    row_dict['default_credentials'] = []
                    row_dict['open_ports'] = []
            else:
                logger.debug(f"No result_path for scan {scan_id}, target {row_dict.get('domain')}")
                row_dict['technologies'] = []
                row_dict['cves'] = []
                row_dict['sensitive_files'] = []
                row_dict['default_credentials'] = []
                row_dict['open_ports'] = []
            results.append(row_dict)

        logger.info(f"Loaded {len(results)} results for scan {scan_id}")
        return results


def get_scans(limit: int = 50) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.*, c.name as config_name, u.username as creator_name
            FROM scans s
            LEFT JOIN scan_configs c ON s.config_id = c.id
            LEFT JOIN users u ON s.created_by = u.id
            ORDER BY s.created_at DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


def get_scan(scan_id: int, user_id: int = None, role: str = None, organization_id: int = None) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        
        try:
            cursor.execute("PRAGMA table_info(scans)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'user_scan_number' not in columns:
                cursor.execute("ALTER TABLE scans ADD COLUMN user_scan_number INTEGER DEFAULT 1")
                logger.info("Added user_scan_number column to scans table (migration)")
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not add user_scan_number column: {e}")
        
        
        if role == 'admin':
            cursor.execute("""
                SELECT s.*, c.name as config_name, c.scan_type, u.username as creator_name
                FROM scans s
                LEFT JOIN scan_configs c ON s.config_id = c.id
                LEFT JOIN users u ON s.created_by = u.id
                WHERE s.id = ?
            """, (scan_id,))
        elif user_id:
            
            cursor.execute("""
                SELECT s.*, c.name as config_name, c.scan_type, u.username as creator_name
                FROM scans s
                LEFT JOIN scan_configs c ON s.config_id = c.id
                LEFT JOIN users u ON s.created_by = u.id
                WHERE s.id = ? AND s.created_by = ?
            """, (scan_id, user_id))
        else:
            
            return None
            
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def get_scan_targets(scan_id: int) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT st.*, t.domain
            FROM scan_targets st
            JOIN targets t ON st.target_id = t.id
            WHERE st.scan_id = ?
            ORDER BY st.id
        """, (scan_id,))
        return [dict(row) for row in cursor.fetchall()]


def update_scan_status(scan_id: int, status: str, progress: int = None):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if progress is not None:
            cursor.execute("""
                UPDATE scans SET status = ?, progress = ?
                WHERE id = ?
            """, (status, progress, scan_id))
        else:
            cursor.execute("""
                UPDATE scans SET status = ? WHERE id = ?
            """, (status, scan_id))
        conn.commit()


def log_access(user_id: int, action: str, resource: str = None,
               ip_address: str = None, status_code: int = 200):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO access_log (user_id, action, resource, ip_address, status_code)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, action, resource, ip_address, status_code))
            conn.commit()
    except sqlite3.OperationalError as e:
        
        logger.debug(f"Could not log access (table may not exist): {e}")
    except Exception as e:
        logger.debug(f"Access logging error: {e}")


def get_dashboard_stats(organization_id: int = None, user_id: int = None) -> Dict[str, Any]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        stats = {}
        
        if user_id is not None:
            
            cursor.execute("SELECT COUNT(*) FROM targets WHERE created_by = ? AND is_active = 1", (user_id,))
            stats['total_targets'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM scans WHERE created_by = ?", (user_id,))
            stats['total_scans'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM scans WHERE created_by = ? AND status = 'running'", (user_id,))
            stats['running_scans'] = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM scans 
                WHERE created_by = ?
                AND status = 'completed' 
                AND strftime('%Y-%m', completed_at) = strftime('%Y-%m', 'now')
            """, (user_id,))
            stats['scans_this_month'] = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM scan_configs 
                WHERE created_by = ? AND is_active = 1 AND schedule_type IS NOT NULL
            """, (user_id,))
            stats['scheduled_scans'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE id = ? AND is_active = 1", (user_id,))
            stats['active_users'] = 1
        elif organization_id is None:
            
            cursor.execute("SELECT COUNT(*) FROM targets WHERE is_active = 1")
            stats['total_targets'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM scans")
            stats['total_scans'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'")
            stats['running_scans'] = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM scans 
                WHERE status = 'completed' 
                AND strftime('%Y-%m', completed_at) = strftime('%Y-%m', 'now')
            """)
            stats['scans_this_month'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM scan_configs WHERE is_active = 1 AND schedule_type IS NOT NULL")
            stats['scheduled_scans'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
            stats['active_users'] = cursor.fetchone()[0]
        else:
            
            cursor.execute("SELECT COUNT(*) FROM targets WHERE organization_id = ? AND is_active = 1", (organization_id,))
            stats['total_targets'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM scans WHERE organization_id = ?", (organization_id,))
            stats['total_scans'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM scans WHERE organization_id = ? AND status = 'running'", (organization_id,))
            stats['running_scans'] = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM scans 
                WHERE organization_id = ?
                AND status = 'completed' 
                AND strftime('%Y-%m', completed_at) = strftime('%Y-%m', 'now')
            """, (organization_id,))
            stats['scans_this_month'] = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM scan_configs 
                WHERE organization_id = ? AND is_active = 1 AND schedule_type IS NOT NULL
            """, (organization_id,))
            stats['scheduled_scans'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE organization_id = ? AND is_active = 1", (organization_id,))
            stats['active_users'] = cursor.fetchone()[0]

        return stats






def get_user_settings(user_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, nvd_api_key, proxy_enabled, proxy_list, max_concurrent_scans,
                   port_scan_enabled, port_scan_with_cves, port_scan_with_exploits,
                   test_default_credentials, search_exploits, updated_at
            FROM user_settings WHERE user_id = ?
        """, (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def create_user_settings(user_id: int, nvd_api_key: str = None, proxy_enabled: bool = False,
                         proxy_list: str = None, max_concurrent_scans: int = 3,
                         port_scan_enabled: bool = False, port_scan_with_cves: bool = False,
                         port_scan_with_exploits: bool = False, test_default_credentials: bool = True,
                         search_exploits: bool = False) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO user_settings (user_id, nvd_api_key, proxy_enabled, proxy_list, max_concurrent_scans,
                                          port_scan_enabled, port_scan_with_cves, port_scan_with_exploits,
                                          test_default_credentials, search_exploits)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, nvd_api_key, proxy_enabled, proxy_list, max_concurrent_scans,
                  port_scan_enabled, port_scan_with_cves, port_scan_with_exploits,
                  test_default_credentials, search_exploits))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def update_user_settings(user_id: int, nvd_api_key: str = None, proxy_enabled: bool = None,
                         proxy_list: str = None, max_concurrent_scans: int = None,
                         port_scan_enabled: bool = None, port_scan_with_cves: bool = None,
                         port_scan_with_exploits: bool = None, test_default_credentials: bool = None,
                         search_exploits: bool = None) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        
        current = get_user_settings(user_id)
        
        if not current:
            
            return create_user_settings(
                user_id=user_id,
                nvd_api_key=nvd_api_key or "",
                proxy_enabled=proxy_enabled or False,
                proxy_list=proxy_list or "",
                max_concurrent_scans=max_concurrent_scans or 3
            )
        
        
        updates = []
        params = []
        
        if nvd_api_key is not None:
            updates.append("nvd_api_key = ?")
            params.append(nvd_api_key)
        
        if proxy_enabled is not None:
            updates.append("proxy_enabled = ?")
            params.append(proxy_enabled)
        
        if proxy_list is not None:
            updates.append("proxy_list = ?")
            params.append(proxy_list)
        
        if max_concurrent_scans is not None:
            updates.append("max_concurrent_scans = ?")
            params.append(max_concurrent_scans)
        
        if updates:
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(user_id)
            
            query = f"UPDATE user_settings SET {', '.join(updates)} WHERE user_id = ?"
            cursor.execute(query, params)
            conn.commit()
            return True
        
        return False


def get_or_create_user_settings(user_id: int) -> Dict[str, Any]:
    settings = get_user_settings(user_id)

    if not settings:
        
        create_user_settings(
            user_id=user_id,
            port_scan_enabled=False,
            port_scan_with_cves=False,
            port_scan_with_exploits=False,
            test_default_credentials=False,  
            search_exploits=False
        )
        settings = get_user_settings(user_id)

    return settings
