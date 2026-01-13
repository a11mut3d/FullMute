# FullMute
A mass website scanner that detects technologies, surveillance cameras, and sensitive files.

This project has room to grow. You can even see some of the initial concepts in the code.
## Peculiarities
- CMS detection (WordPress, Joomla, Drupal, Magento, Shopify, etc.)
- Definition of web servers (Nginx, Apache, IIS, LiteSpeed)
- Framework detection (Laravel, Django, Ruby on Rails, etc.)
- Search for surveillance cameras (Axis, Hikvision, Dahua, Ubiquiti, etc.)
- Checking sensitive files (.env, .git, config.php, backup files)
- Asynchronous scanning with proxy support
- User-Agent Rotation and Random Delays
- SQLite database for storing results
- Extensibility by changing config
## Installation
``` bash
git clone https://github.com/yourusername/fullmute.git
cd fullmute
pip install -e .
```
## Requirements
- Python 3.8 or higher
- Installed dependencies from requirements.txt
## Usage
### Basic commands
Database initialization
``` bash
fullmute init database.db
```
Scanning domains from a file
``` bash
fullmute scan domains.txt --output results.json --max-concurrent 10 --timeout 15 --proxy
```
### scan command options
- ```--output, -o``` - File to save results to (default: scan_results.json)
- ```-max-concurrent, -c``` - Maximum number of concurrent requests (default: 10)
- ```-timeout, -t``` - Request timeout in seconds (default: 15)
- ```-proxy``` - Use proxy from proxies.txt
- ```-delay-min``` - Minimum delay between requests (default: 1.0)
- ```-delay-max``` - Maximum delay between requests (default: 3.0)
### Scanning one domain
``` bash
fullmute scan-one example.com
```
Exporting results from the database
``` bash
fullmute export database.db --format json
fullmute export database.db --format csv
```
## Input file format
### File with domains
Each line contains one domain or IP address:
``` txt
example.com
github.com
192.168.1.100
subdomain.example.org
```
### Proxy file
Каждая строка содержит прокси в формате:
``` txt
protocol://host:port
```
## Results Format
### JSON output
``` json
{
  "domain": "example.com",
  "status_code": 200,
  "technologies": {
    "cms": ["WordPress"],
    "server": ["Nginx"],
    "framework": ["Laravel"],
    "camera": ["Axis"]
  },
  "sensitive_files": [
    {
      "file_type": ".env",
      "url": "http://example.com/.env",
      "verification_result": "verified",
      "content_sample": "DB_PASSWORD=secret123",
      "status_code": 200
    }
  ],
  "error": null
}
```
### CSV export
When exporting to CSV, a file is created with the following columns:
- domain
- scanned_at
- has_camera
- is_alive
- response_time
- http_status
- technologies
- sensitive_files
## Custom signatures
Signatures are stored in JSON files in the ```config/signatures/``` directory. You can add your own signatures or edit existing ones.
### Signature format
``` json
{
  "TechnologyName": {
    "headers": ["Header: Pattern"],
    "html": ["HTML pattern"],
    "urls": ["/specific-path"],
    "cookies": ["cookie_name_pattern"],
    "must_have": ["required_pattern"],
    "must_not_have": ["exclusion_pattern"],
    "confidence": 90
  }
}
```
## About the creator: 
### **Author:** [allmuted](https://github.com/a11mut3d)
### **Telegram channel:** https://t.me/rootlocalhostvibe
