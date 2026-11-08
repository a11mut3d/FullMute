
# FullMute
<img width="2880" height="1920" alt="image" src="https://github.com/user-attachments/assets/2e6454bd-791d-430e-9250-7cb319c83649" />

**Advanced Web Security Scanner** — A comprehensive security assessment tool with both CLI and web interface for detecting technologies, vulnerabilities, sensitive files, and default credentials.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)

---

## Table of Contents

* [Features](#features)
* [Installation](#installation)
* [Quick Start](#quick-start)
* [Automated Tests](#automated-tests)
* [CLI Usage](#cli-usage)
* [Web Interface](#web-interface)
* [Configuration](#configuration)
* [License](#license)

---

## Features

* **Technology Detection**: CMS, frameworks, servers, databases, JavaScript libraries, devices.
* **Vulnerability Discovery**: CVE lookup, exploit search.
* **Sensitive File Detection**: Automated scanning for sensitive files.
* **Default Credential Testing**: Default credentials testing.
* **Port Scanning**: Port scanning and service identification.
* **Cloudflare Bypass**: Cloudflare bypass attempts.
* **Scheduled Scans**: Automated scan scheduling.

---

## Installation

### Prerequisites

* Python 3.10 or higher
* pip
* SQLite3
* searchsploit

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd FullMute
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Install Package

```bash
pip install -e .
```

### Step 4: Install searchsploit (Optional)

```bash
https://www.exploit-db.com/searchsploit
```

---

## Automated Tests

The local test suite uses only fixtures and temporary SQLite databases; it does
not scan external hosts or call external vulnerability services.

```bash
PYTHONPATH=src python -m unittest discover -s test -v
```

Run this from the repository root. If using a virtual environment, replace
`python` with its interpreter path, for example `venv/bin/python`.

---

## Quick Start

### CLI Mode

```bash
# Initialize scanner database
fullmute init /fullmute.db

# Scan domains from a file
fullmute scan targets.txt

# Run technology detection only (no NVD or additional checks)
fullmute scan targets.txt --only-technologies

# Select individual stages
fullmute scan targets.txt --cves --no-exploits --no-nuclei --no-port-scan

# Run all checks and save one combined JSON report
fullmute scan targets.txt --full -o full_scan_results.json

# Full mode, but skip Nuclei and default-credential checks
fullmute scan targets.txt --full --no-nuclei --no-default-credentials

# Scan a single domain
fullmute scan-one example.com

# Find a specific sensitive file across scanned domains
fullmute search fullmute.db --search-type sensitive-file --query .env

# Search for a particular technology
fullmute search fullmute.db --search-type technology --query WordPress

# Find WordPress installations with an exact version or inclusive version range
fullmute search fullmute.db --search-type version --query "WordPress 3.6.0"
fullmute search fullmute.db --search-type version --query "WordPress 3.6.0 - 7.0.1"

# Start web interface
fullmute web start
```

### Web Interface

```bash
# Initialize web database
fullmute web init

# Start the web server
fullmute web start
```

Access the web interface at: **[http://localhost:8080](http://localhost:8080)**

---

## CLI Usage

### Commands

#### `fullmute init`

Initialize the scanner database.

#### `fullmute scan <file>`

Scan multiple domains from a file.

Scan stages can be selected independently on `scan` and (except port scanning)
`scan-one`:

| Option | What it controls |
| --- | --- |
| `--technologies` / `--no-technologies` | Technology fingerprinting |
| `--cves` / `--no-cves` | NVD CVE lookups for detected, versioned technologies (enabled by default) |
| `--exploits` / `--no-exploits` | Exploit-DB lookup for CVEs |
| `--nuclei` / `--no-nuclei` | Run matching local Nuclei templates against the target |
| `--port-scan` / `--no-port-scan` | Scan ports and identify services |
| `--sensitive-files` / `--no-sensitive-files` | Check for sensitive files |
| `--default-credentials` / `--no-default-credentials` | Test detected login forms/services for default credentials |
| `--only-technologies` | Shorthand for technology detection without CVE, Exploit-DB, Nuclei, port, sensitive-file, or credential checks |
| `--full` | Enable all stages; explicit `--no-*` flags override it |

Exploit-DB and Nuclei require CVE lookup. Disabling CVEs also disables those
dependent stages unless they were explicitly enabled, which is rejected with a
usage error. Existing YAML settings remain defaults when the corresponding CLI
option is omitted; explicit CLI flags override both YAML settings and `--full`.
For example, scan technologies and CVEs without running exploit searches,
Nuclei, or ports:

```bash
fullmute scan targets.txt --technologies --cves --no-exploits --no-nuclei --no-port-scan
```

For authorized internal assessments, private targets remain protected by the
SSRF check unless their CIDR is explicitly allowed on the CLI:

```bash
fullmute scan internal-targets.txt --allow-private-network 192.168.1.0/24
```

The scanner database path is configured by `database.path` in `config.yaml`.
Relative database paths are resolved from the directory containing the config
file, so launching FullMute from another working directory uses the same
database. Use `fullmute --config /path/to/config.yaml scan targets.txt` to select
a specific configuration. The scanner checks the same admin/login paths with
bounded concurrency; adjust `scanner.login_path_probe_concurrency` in the YAML
configuration if needed (default: `8`). Per-domain timing is recorded in the
scanner log to identify the slowest stages. HTTP response bodies are capped at
5 MiB by default (`scanner.max_response_bytes`) to prevent oversized pages from
causing unbounded memory use. Completed web scans release their in-memory
results after persistence; cancelled or expired scans keep their queue slot
until the worker exits, preventing overlapping orphaned scans.
Sensitive-file checks run common exposure signatures first, then probe only
the detected WordPress, Joomla, Bitrix, or Shopify paths from
`cms_sensitive_files.json`. CMS probes are bounded by
`scanner.sensitive_file_concurrency` (default: `8`), do not follow redirects,
and report endpoint reachability without storing response contents.
Versioned technologies are checked against NVD using an exact CPE query first.
If NVD has no matching CPE or exact query returns no CVEs, FullMute retries with
a product-and-version keyword query and verifies each result against NVD's
affected CPE configuration. A CVE is included only when that technology is
explicitly marked vulnerable and its exact version or affected-version range
matches the detected version. Unbounded wildcard CPE entries and keyword-only
results without structured affected-version data are excluded to avoid
reporting old plugin or product vulnerabilities against unrelated current
versions. When an NVD lookup completes successfully, stored CVEs for that
technology/version are replaced with the current matches; failed lookups leave
existing database findings intact.

#### `fullmute scan-one <domain>`

Scan a single domain.

#### `fullmute search <db_path>`

Search the scanner database. Run `fullmute search --help` to see all arguments,
options, supported search types, and examples.

Relative database paths are resolved from the current working directory first,
then from the selected config file's directory, matching scan database paths.
For example, `fullmute --config /path/to/config.yaml search fullmute.db -t cve
-q CVE-2024` searches the configured project's database even when launched
from another directory.

Supported search types: `cve`, `cms`, `plugin`, `technology`, `domain`, `server`,
`database`, `language`, `version`, and `sensitive-file`.

Version searches match the technology name and either one exact numeric version
or an inclusive numeric version range. For example:

```bash
fullmute search fullmute.db -t version -q "WordPress 3.6.0"
fullmute search fullmute.db -t version -q "WordPress 3.6.0 - 7.0.1"
```

For an exact sensitive file name across all saved domains, use:

```bash
fullmute search fullmute.db --search-type sensitive-file --query .env
fullmute search fullmute.db -t sensitive-file -q wp-config.php
```

The sensitive-file query matches the exact saved URL/path or a path ending in
that filename, and prints the domain, path, file type, verification result, and
discovery time.

Every command documents its own parameters: use `fullmute --help` for command
names and `fullmute COMMAND --help` (for example `fullmute scan --help`) for
that command's complete options.

#### `fullmute web start`

Start the web server.

#### `fullmute web init`

Initialize the web database with the default admin user.

---

## Web Interface

Main pages:

* **Dashboard** — Overview of scans, statistics.
* **Targets** — Manage target domains.
* **Scans** — View scan history.
* **New Scan** — Create a new scan.
* **Reports** — Generate PDF reports.
* **Settings** — Admin configuration.

Authentication uses JWT tokens, CSRF tokens, and rate limiting.

---

MIT License - See LICENSE file for details.

---

**FullMute** — Comprehensive security scanning for modern web applications.

---

**[Mute Ecosystem](https://a11mut3d.github.io/MuteEcosystem/)** 
# Nuclei CVE verification

FullMute can optionally verify detected CVEs with matching local Nuclei templates. Put the
official templates in `./nuclei-templates` (or set `FULLMUTE_NUCLEI_TEMPLATES_PATH`), and
make the `nuclei` executable available in `PATH` (or set `FULLMUTE_NUCLEI_BINARY`). Enable
**Run Nuclei CVE Templates** in **My Settings**. FullMute then maps `CVE-2026-0137` to a
matching YAML template automatically. Results are stored with the scan in the web database.
The scan details page provides download and edit actions for templates that were executed.
