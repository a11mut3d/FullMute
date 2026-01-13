SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    has_camera BOOLEAN DEFAULT 0,
    is_alive BOOLEAN DEFAULT 1,
    response_time INTEGER,
    http_status INTEGER,
    technologies TEXT,
    sensitive_files TEXT
);

CREATE TABLE IF NOT EXISTS technologies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER,
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    detection_method TEXT,
    confidence INTEGER,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, name, version),
    FOREIGN KEY (domain_id) REFERENCES domains (id)
);

CREATE TABLE IF NOT EXISTS sensitive_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER,
    file_path TEXT NOT NULL,
    file_type TEXT,
    verification_result TEXT,
    content_sample TEXT,
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, file_path),
    FOREIGN KEY (domain_id) REFERENCES domains (id)
);

CREATE TABLE IF NOT EXISTS http_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    content BLOB,
    headers TEXT,
    status_code INTEGER,
    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_domains_scanned ON domains(scanned_at);
CREATE INDEX IF NOT EXISTS idx_tech_domain ON technologies(domain_id);
CREATE INDEX IF NOT EXISTS idx_tech_name ON technologies(name, version);
CREATE INDEX IF NOT EXISTS idx_files_domain ON sensitive_files(domain_id);
CREATE INDEX IF NOT EXISTS idx_cache_url ON http_cache(url);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON http_cache(expires_at);
"""
