
# FullMute

**Advanced Web Security Scanner** — A comprehensive security assessment tool with both CLI and web interface for detecting technologies, vulnerabilities, sensitive files, and default credentials.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)

---

## Table of Contents

* [Features](#features)
* [Installation](#installation)
* [Quick Start](#quick-start)
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

## Quick Start

### CLI Mode

```bash
# Initialize scanner database
fullmute init

# Scan domains from a file
fullmute scan targets.txt

# Scan a single domain
fullmute scan-one example.com

# Search scan results
fullmute search

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

#### `fullmute scan-one <domain>`

Scan a single domain.

#### `fullmute search`

Search through scan results.

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
