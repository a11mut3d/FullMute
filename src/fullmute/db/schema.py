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

CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    technology_id INTEGER,
    cve_id TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    cvss_score REAL,
    cvss_version TEXT,
    published_date TIMESTAMP,
    last_modified TIMESTAMP,
    vector_string TEXT,
    references_json TEXT,
    FOREIGN KEY (technology_id) REFERENCES technologies (id)
);

CREATE TABLE IF NOT EXISTS plugins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER,
    cms_type TEXT NOT NULL,
    plugin_name TEXT NOT NULL,
    version TEXT,
    status TEXT DEFAULT 'active',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, cms_type, plugin_name, version),
    FOREIGN KEY (domain_id) REFERENCES domains (id)
);

CREATE TABLE IF NOT EXISTS plugin_cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_id INTEGER,
    cve_id TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    cvss_score REAL,
    cvss_version TEXT,
    published_date TIMESTAMP,
    last_modified TIMESTAMP,
    vector_string TEXT,
    references_json TEXT,
    FOREIGN KEY (plugin_id) REFERENCES plugins (id)
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
CREATE INDEX IF NOT EXISTS idx_cves_tech ON cves(technology_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_score ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_plugins_domain ON plugins(domain_id);
CREATE INDEX IF NOT EXISTS idx_plugins_cms ON plugins(cms_type);
CREATE INDEX IF NOT EXISTS idx_plugins_name ON plugins(plugin_name);
CREATE INDEX IF NOT EXISTS idx_plugin_cves_plugin ON plugin_cves(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_cves_severity ON plugin_cves(severity);
CREATE INDEX IF NOT EXISTS idx_plugin_cves_score ON plugin_cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_files_domain ON sensitive_files(domain_id);
CREATE INDEX IF NOT EXISTS idx_cache_url ON http_cache(url);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON http_cache(expires_at);
"""
