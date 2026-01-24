# FullMute Scanner

FullMute is a powerful web scanning tool that identifies CMS, frameworks, web servers, routers, cameras, JavaScript libraries, programming languages, databases, plugins, and themes with CVE vulnerability checking.

## Features

- **Technology Detection**: Identifies CMS (WordPress, Joomla, Drupal, etc.), frameworks, web servers, routers, cameras
- **Language & Database Detection**: PHP, Python, Java, Node.js, MySQL, PostgreSQL, MongoDB, etc.
- **Plugin & Theme Detection**: Automatically detects installed CMS plugins and themes
- **CVE Checking**: Automatic vulnerability checking for all detected technologies and versions
- **Database Search**: Search command for various criteria (CVE, CMS, technologies, etc.)
- **Database Storage**: All data stored in SQLite database
- **Multithreading**: Supports parallel scanning of multiple domains

## Installation

```bash
git clone <repository-url>
cd FullMute
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
```

## Usage

### Scan a single domain

```bash
fullmute scan-one example.com
```

### Scan a list of domains from file

```bash
fullmute scan domains.txt
```

### Initialize database

```bash
fullmute init fullmute.db
```

### Search in database

```bash
# Search by CVE
fullmute search fullmute.db -t cve -q "CVE-2021"

# Search by CMS
fullmute search fullmute.db -t cms -q "WordPress"

# Search by plugins
fullmute search fullmute.db -t plugin -q "akismet"

# Search by domains
fullmute search fullmute.db -t domain -q "example.com"

# Search by technologies
fullmute search fullmute.db -t technology -q "nginx"

# Search by web servers
fullmute search fullmute.db -t server -q "Apache"

# Search by databases
fullmute search fullmute.db -t database -q "MySQL"

# Search by programming languages
fullmute search fullmute.db -t language -q "PHP"
```

### View statistics

```bash
fullmute stats fullmute.db
```

### Export results

```bash
fullmute export fullmute.db --format json
```

## Capabilities

### CMS and Framework Detection
- WordPress, Joomla, Drupal, Magento, Shopify and others
- Laravel, Django, Ruby on Rails, Express.js and others

### Web Server Detection
- Apache, Nginx, Microsoft-IIS, LiteSpeed, OpenResty and others

### Router Detection
- Cisco, D-Link, Netgear, Linksys, ASUS, Huawei, MikroTik, Ubiquiti and others

### Camera Detection
- Axis, Hikvision, Dahua, Vivotek, Bosch and others

### JavaScript Library Detection
- jQuery, React, Vue.js, Angular, Bootstrap and others

### Programming Language Detection
- PHP, Python, Java, Node.js, Ruby, Go, C# and others

### Database Detection
- MySQL, PostgreSQL, MongoDB, Redis, SQLite, Oracle and others

### Plugin and Theme Detection
- Automatic detection of installed CMS plugins and themes
- Support for WordPress, Joomla, Drupal and other CMS

### CVE Checking
- Automatic vulnerability checking through NVD API
- Shows threat level and CVSS scores
- Stores CVE information in database

## Architecture

- **CLI**: Command-line interface for user interaction
- **Core**: Main scanning logic and orchestration
- **Detector**: Modules for detecting various technologies
- **Utils**: Utility functions (HTTP client, stealth functions, etc.)
- **DB**: Database operations (schema, queries)

## Configuration

Configuration file `config.yaml` allows customization of scanning parameters:

```yaml
scanner:
  max_concurrent: 10
  timeout: 15
  proxy_enabled: false
  min_delay: 1.0
  max_delay: 3.0

database:
  path: fullmute.db
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/NewFeature`)
3. Commit changes (`git commit -m 'Add New Feature'`)
4. Push to the branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

## License
creator: https://t.me/KuniDeveloper

MIT License
