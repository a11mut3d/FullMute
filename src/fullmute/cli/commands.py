import click
import builtins
import json
import asyncio
from pathlib import Path
from fullmute.core.orchestrator import ScanOrchestrator
from fullmute.detector.signature_loader import SignatureLoader
from fullmute.db.engine import init_db
from fullmute.utils.logger import setup_logger

logger = setup_logger()

@click.group()
@click.option(
    '--config',
    default='config.yaml',
    show_default=True,
    type=click.Path(dir_okay=False),
    help='Path to the YAML configuration file.',
)
@click.pass_context
def cli(ctx, config):
    """FullMute scanner: scan targets and search saved results.

    Run ``fullmute COMMAND --help`` to see every option for a command.

    \b
    Examples:
      fullmute search --help
      fullmute scan --help
      fullmute port scan --help
    """
    ctx.ensure_object(dict)
    ctx.obj['config'] = config


from fullmute.scanner.cli import port
cli.add_command(port)


@cli.group()
def web():
    pass

@web.command()
@click.option('--username', '-u', default='admin', help='Admin username')
@click.option('--role', '-r', default='admin', type=click.Choice(['admin', 'viewer']), help='User role')
def init(username, role):
    try:
        from fullmute.web.database import init_web_db, create_user, generate_api_key
        
        click.echo("\n    ╔═══════════════════════════════════════════════════════╗")
        click.echo("    ║   FullMute Web Interface Setup                        ║")
        click.echo("    ╚═══════════════════════════════════════════════════════╝\n")
        
        click.echo("[*] Initializing database...")
        init_web_db()
        click.echo("[+] Database initialized successfully")
        
        click.echo(f"\n[*] Creating {role} user '{username}'...")
        
        api_key = generate_api_key()
        user_id = create_user(username=username, api_key=api_key, role=role)
        
        if user_id:
            click.echo("[+] User created successfully!\n")
            click.echo("=" * 60)
            click.echo(" IMPORTANT: Save this API key!")
            click.echo("=" * 60)
            click.echo(f"\n  Username: {username}")
            click.echo(f"  Role: {role}")
            click.echo(f"  API Key: {api_key}")
            click.echo("\n" + "=" * 60)
            click.echo(" This key will NOT be shown again!")
            click.echo("=" * 60)
            click.echo("\nYou can now start the web server with:")
            click.echo("  fullmute web start\n")
        else:
            click.echo(f"[-] User '{username}' already exists!")
            click.echo("    Use 'fullmute web list-users' to see existing users\n")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@web.command()
@click.option('--host', '-h', default=None, help='Host to bind to')
@click.option('--port', '-p', default=None, type=int, help='Port to bind to')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def start(host, port, debug):
    try:
        import uvicorn
        from fullmute.web.config import config
        from fullmute.web.database import init_web_db, generate_api_key, create_user, list_users
        from pathlib import Path
        
        if host:
            config.host = host
        if port:
            config.port = port
        if debug:
            config.debug = debug
        
        click.echo("\n    ╔═══════════════════════════════════════════════════════╗")
        click.echo("    ║   FullMute Web Interface                              ║")
        click.echo("    ╚═══════════════════════════════════════════════════════╝\n")
        
        db_path = Path(config.database_path)
        if not db_path.exists():
            click.echo("[*] Database not found. Initializing...")
            init_web_db()
            click.echo("[+] Database initialized")
            
            if not list_users():
                click.echo("\n[*] No users found. Creating default admin user...")
                api_key = generate_api_key()
                create_user(username='admin', api_key=api_key, role='admin')
                click.echo("\n" + "=" * 60)
                click.echo(" DEFAULT ADMIN USER CREATED")
                click.echo("=" * 60)
                click.echo(f"\n  Username: admin")
                click.echo(f"  API Key: {api_key}")
                click.echo("\n" + "=" * 60 + "\n")
        
        click.echo(f"[*] Starting web server on http://{config.host}:{config.port}")
        click.echo("[*] Press Ctrl+C to stop\n")
        
        uvicorn.run(
            "fullmute.web.app:app",
            host=config.host,
            port=config.port,
            reload=config.debug,
            log_level="info"
        )
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@web.command()
def list_users():
    try:
        from fullmute.web.database import list_users
        
        users = list_users()
        
        if not users:
            click.echo("No users found. Run 'fullmute web init' to create admin user.\n")
            return
        
        click.echo("\n" + "=" * 60)
        click.echo(" FullMute Web Users")
        click.echo("=" * 60)
        click.echo(f"{'Username':<20} {'Role':<10} {'API Key Prefix':<20} {'Status':<10}")
        click.echo("-" * 60)
        
        for user in users:
            status = "Active" if user['is_active'] else "Inactive"
            click.echo(f"{user['username']:<20} {user['role']:<10} {user['api_key_prefix']:<20} {status:<10}")
        
        click.echo("=" * 60 + "\n")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@web.command()
@click.option('--username', '-u', required=True, help='Username for new API key')
def regenerate_key(username):
    try:
        from fullmute.web.database import list_users, regenerate_api_key
        
        users = list_users()
        user = next((u for u in users if u['username'] == username), None)
        
        if not user:
            click.echo(f"[-] User '{username}' not found!")
            return
        
        new_key = regenerate_api_key(user['id'])
        
        if new_key:
            click.echo("[+] API key regenerated successfully!\n")
            click.echo("=" * 60)
            click.echo(f"  Username: {username}")
            click.echo(f"  New API Key: {new_key}")
            click.echo("=" * 60)
            click.echo("\n⚠️  The old API key is now invalid!\n")
        else:
            click.echo("[-] Failed to regenerate API key\n")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@web.command()
def status():
    try:
        from fullmute.web.config import config
        from fullmute.web.database import list_users, get_scan_configs
        from pathlib import Path
        
        click.echo("\n    ╔═══════════════════════════════════════════════════════╗")
        click.echo("    ║   FullMute Web Status                                 ║")
        click.echo("    ╚═══════════════════════════════════════════════════════╝\n")
        
        click.echo("=" * 60)
        click.echo(" FullMute Web Status")
        click.echo("=" * 60)
        
        db_path = Path(config.database_path)
        scanner_db = Path(config.scanner_database)
        
        click.echo(f"\n📊 Configuration:")
        click.echo(f"   Host: {config.host}")
        click.echo(f"   Port: {config.port}")
        click.echo(f"   Debug: {config.debug}")
        
        click.echo(f"\n💾 Database:")
        click.echo(f"   Web DB: {db_path} [{'✓' if db_path.exists() else '✗'}]")
        click.echo(f"   Scanner DB: {scanner_db} [{'✓' if scanner_db.exists() else '✗'}]")
        
        users = list_users()
        click.echo(f"\n👥 Users: {len(users)}")
        
        if users:
            admins = sum(1 for u in users if u['role'] == 'admin')
            viewers = sum(1 for u in users if u['role'] == 'viewer')
            click.echo(f"   Admins: {admins}")
            click.echo(f"   Viewers: {viewers}")
        
        try:
            configs = get_scan_configs()
            scheduled = sum(1 for c in configs if c.get('schedule_type'))
            click.echo(f"\n📅 Scheduled Scans: {scheduled}")
        except Exception:
            click.echo(f"\n📅 Scheduled Scans: N/A (tables not initialized)")
        
        click.echo("\n" + "=" * 60 + "\n")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.argument('db_path')
def init(db_path):
    try:
        init_db(db_path)
        click.echo(f"Database initialized at {db_path}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.argument(
    'db_path',
    metavar='DB_PATH',
    type=click.Path(dir_okay=False, readable=True),
)
@click.option(
    '--search-type',
    '-t',
    type=click.Choice([
        'cve', 'cms', 'plugin', 'technology', 'domain', 'server',
        'database', 'language', 'sensitive-file',
    ]),
    required=True,
    help=(
        'Search category: cve, cms, plugin, technology, domain, server, '
        'database, language, or sensitive-file.'
    ),
)
@click.option(
    '--query',
    '-q',
    required=True,
    metavar='TEXT',
    help=(
        'Text to find. For sensitive-file, use a file name (for example '
        '".env") or an exact stored URL/path.'
    ),
)
@click.pass_context
def search(ctx, db_path, search_type, query):
    """Search saved scanner database results.

    Sensitive-file searches match one exact file name across domains, or an
    exact stored path/URL.

    \b
    Examples:
      fullmute search fullmute.db -t sensitive-file -q .env
      fullmute search fullmute.db -t sensitive-file -q /wp-config.php
      fullmute search fullmute.db -t cve -q CVE-2024
      fullmute search fullmute.db -t technology -q WordPress
    """
    file_query = query.strip()
    if search_type == 'sensitive-file' and not file_query:
        raise click.BadParameter(
            'A file name or path is required for sensitive-file search.',
            ctx=ctx,
            param_hint='--query',
        )

    database_path = Path(db_path).expanduser()
    if not database_path.is_absolute():
        working_directory_path = database_path.resolve()
        if working_directory_path.is_file():
            database_path = working_directory_path
        else:
            config_path = Path(ctx.obj['config']).expanduser().resolve()
            config_directory_path = (config_path.parent / database_path).resolve()
            if config_directory_path.is_file():
                database_path = config_directory_path
            else:
                raise click.BadParameter(
                    f"Database not found at {working_directory_path} or "
                    f"{config_directory_path}. Use the scanner DB path from "
                    "database.path in your config.",
                    ctx=ctx,
                    param_hint='DB_PATH',
                )
    elif not database_path.is_file():
        raise click.BadParameter(
            f"Database file not found: {database_path}",
            ctx=ctx,
            param_hint='DB_PATH',
        )
    db_path = str(database_path.resolve())

    try:
        from fullmute.db.queries import DBQueries
        db = DBQueries(db_path)

        results = []

        if search_type == 'sensitive-file':
            import sqlite3

            escaped_query = (
                file_query.lstrip('/')
                .replace('\\', '\\\\')
                .replace('%', '\\%')
                .replace('_', '\\_')
            )
            conn = sqlite3.connect(db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    r'''
                    SELECT DISTINCT d.domain, sf.file_path, sf.file_type,
                                    sf.verification_result, sf.found_at
                    FROM domains d
                    JOIN sensitive_files sf ON d.id = sf.domain_id
                    WHERE lower(sf.file_path) = lower(?)
                       OR lower(sf.file_path) LIKE lower(?) ESCAPE '\'
                    ORDER BY d.domain, sf.file_path
                    ''',
                    (file_query, f'%/{escaped_query}'),
                )
                results = cursor.fetchall()
            finally:
                conn.close()

            if results:
                click.echo(
                    f"\nFound {len(results)} sensitive-file result(s) for "
                    f"'{file_query}':"
                )
                for domain, file_path, file_type, verification, found_at in results:
                    click.echo(f"  Domain: {domain}")
                    click.echo(f"    File: {file_path}")
                    click.echo(f"    Type: {file_type or 'unknown'}")
                    click.echo(f"    Verification: {verification or 'unknown'}")
                    click.echo(f"    Found: {found_at or 'unknown'}")
                    click.echo()
            else:
                click.echo(f"No sensitive files found matching '{file_query}'")

        elif search_type == 'cve':
            
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT DISTINCT d.domain, t.name, t.version, c.cve_id, c.severity, c.cvss_score
                FROM domains d
                JOIN technologies t ON d.id = t.domain_id
                JOIN cves c ON t.id = c.technology_id
                WHERE c.cve_id LIKE ?
            ''', (f'%{query}%',))

            results = cursor.fetchall()
            conn.close()

            if results:
                click.echo(f"\nFound {len(results)} results for CVE '{query}':")
                for domain, tech_name, tech_version, cve_id, severity, score in results:
                    click.echo(f"  Domain: {domain}")
                    click.echo(f"    Technology: {tech_name} ({tech_version})")
                    click.echo(f"    CVE: {cve_id} (Severity: {severity}, Score: {score})")
                    click.echo()
            else:
                click.echo(f"No domains found with CVE containing '{query}'")

        elif search_type == 'cms':
            
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT DISTINCT d.domain, t.name, t.version
                FROM domains d
                JOIN technologies t ON d.id = t.domain_id
                WHERE t.category = 'cms' AND t.name LIKE ?
            ''', (f'%{query}%',))

            results = cursor.fetchall()
            conn.close()

            if results:
                click.echo(f"\nFound {len(results)} domains with CMS containing '{query}':")
                for domain, cms_name, version in results:
                    version_str = f" ({version})" if version else ""
                    click.echo(f"  {domain}: {cms_name}{version_str}")
            else:
                click.echo(f"No domains found with CMS containing '{query}'")

        elif search_type == 'plugin':
            
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT DISTINCT d.domain, p.plugin_name, p.version, p.cms_type
                FROM domains d
                JOIN plugins p ON d.id = p.domain_id
                WHERE p.plugin_name LIKE ?
            ''', (f'%{query}%',))

            results = cursor.fetchall()
            conn.close()

            if results:
                click.echo(f"\nFound {len(results)} domains with plugin containing '{query}':")
                for domain, plugin_name, version, cms_type in results:
                    version_str = f" ({version})" if version else ""
                    click.echo(f"  {domain}: {plugin_name}{version_str} [{cms_type}]")
            else:
                click.echo(f"No domains found with plugin containing '{query}'")

                
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM plugins')
                plugin_count = cursor.fetchone()[0]
                conn.close()

                if plugin_count > 0:
                    click.echo(f"Note: There are {plugin_count} plugins in the database, but none match '{query}'")
                else:
                    click.echo("Note: No plugins found in the database")

        elif search_type == 'technology':
            
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT DISTINCT d.domain, t.category, t.name, t.version
                FROM domains d
                JOIN technologies t ON d.id = t.domain_id
                WHERE t.name LIKE ? OR t.category LIKE ?
            ''', (f'%{query}%', f'%{query}%'))

            results = cursor.fetchall()
            conn.close()

            if results:
                click.echo(f"\nFound {len(results)} domains with technology containing '{query}':")
                for domain, category, tech_name, version in results:
                    version_str = f" ({version})" if version else ""
                    click.echo(f"  {domain}: {category} -> {tech_name}{version_str}")
            else:
                click.echo(f"No domains found with technology containing '{query}'")

        elif search_type == 'domain':
            
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT domain, scanned_at, http_status, has_camera
                FROM domains
                WHERE domain LIKE ?
            ''', (f'%{query}%',))

            results = cursor.fetchall()
            conn.close()

            if results:
                click.echo(f"\nFound {len(results)} domains matching '{query}':")
                for domain, scanned_at, http_status, has_camera in results:
                    camera_status = "YES" if has_camera else "NO"
                    click.echo(f"  Domain: {domain}")
                    click.echo(f"    Scanned: {scanned_at}")
                    click.echo(f"    Status: {http_status}")
                    click.echo(f"    Has Camera: {camera_status}")
                    click.echo()
            else:
                click.echo(f"No domains found matching '{query}'")

        elif search_type == 'server':
            
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT DISTINCT d.domain, t.name, t.version
                FROM domains d
                JOIN technologies t ON d.id = t.domain_id
                WHERE t.category = 'server' AND t.name LIKE ?
            ''', (f'%{query}%',))

            results = cursor.fetchall()
            conn.close()

            if results:
                click.echo(f"\nFound {len(results)} domains with server containing '{query}':")
                for domain, server_name, version in results:
                    version_str = f" ({version})" if version else ""
                    click.echo(f"  {domain}: {server_name}{version_str}")
            else:
                click.echo(f"No domains found with server containing '{query}'")

        elif search_type == 'database':
            
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT DISTINCT d.domain, t.name, t.version
                FROM domains d
                JOIN technologies t ON d.id = t.domain_id
                WHERE t.category = 'database' AND t.name LIKE ?
            ''', (f'%{query}%',))

            results = cursor.fetchall()
            conn.close()

            if results:
                click.echo(f"\nFound {len(results)} domains with database containing '{query}':")
                for domain, db_name, version in results:
                    version_str = f" ({version})" if version else ""
                    click.echo(f"  {domain}: {db_name}{version_str}")
            else:
                click.echo(f"No domains found with database containing '{query}'")

        elif search_type == 'language':
            
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT DISTINCT d.domain, t.name, t.version
                FROM domains d
                JOIN technologies t ON d.id = t.domain_id
                WHERE t.category = 'language' AND t.name LIKE ?
            ''', (f'%{query}%',))

            results = cursor.fetchall()
            conn.close()

            if results:
                click.echo(f"\nFound {len(results)} domains with programming language containing '{query}':")
                for domain, lang_name, version in results:
                    version_str = f" ({version})" if version else ""
                    click.echo(f"  {domain}: {lang_name}{version_str}")
            else:
                click.echo(f"No domains found with programming language containing '{query}'")

    except Exception as e:
        click.echo(f"Error during search: {e}", err=True)

@cli.command()
@click.argument('domains_file')
@click.option('--output', '-o', default='scan_results.json', help='Output file')
@click.option('--max-concurrent', '-c', default=10, help='Max concurrent requests')
@click.option('--timeout', '-t', default=15, help='Request timeout')
@click.option('--proxy', is_flag=True, help='Use proxies')
@click.option('--delay-min', default=1.0, help='Minimum delay between requests')
@click.option('--delay-max', default=3.0, help='Maximum delay between requests')
@click.option('--full', is_flag=True, help='Run web, CVE, Nuclei, Exploit-DB and port scans')
@click.pass_context
def scan(ctx, domains_file, output, max_concurrent, timeout, proxy, delay_min, delay_max, full):
    domains_file = Path(domains_file).resolve()
    
    if not domains_file.exists():
        click.echo(f"Error: File {domains_file} not found", err=True)
        return
    
    if not domains_file.is_file():
        click.echo(f"Error: {domains_file} is not a file", err=True)
        return
    
    if domains_file.suffix.lower() != '.txt':
        click.echo(f"Error: File must have .txt extension", err=True)
        return
    
    file_path_str = str(domains_file)
    dangerous_patterns = ['\x00', '..', '~']
    for pattern in dangerous_patterns:
        if pattern in file_path_str:
            click.echo(f"Error: Invalid file path", err=True)
            return
    
    output_path = Path(output).expanduser().resolve()
    system_dirs = ['/etc', '/usr', '/bin', '/sbin', '/var', '/proc', '/sys']
    for sys_dir in system_dirs:
        if str(output_path).startswith(sys_dir):
            click.echo("Error: Cannot write to system directory", err=True)
            return
    
    try:
        orchestrator = ScanOrchestrator(ctx.obj['config'])

        config = orchestrator.config
        scanner_config = config.setdefault('scanner', {})
        scanner_config['max_concurrent'] = max_concurrent
        scanner_config['timeout'] = timeout
        scanner_config['proxy_enabled'] = proxy
        scanner_config['min_delay'] = delay_min
        scanner_config['max_delay'] = delay_max
        if full:
            click.echo("Full mode: web, CVE, Nuclei, Exploit-DB and port scanning enabled")

        results = asyncio.run(orchestrator.scan_from_file(
            str(domains_file),
            output_file=str(output_path),
            full=full,
        ))

        scanned_results = [
            result for result in results
            if isinstance(result, dict)
        ]
        domains_with_cves = 0
        total_cves = 0
        for result in scanned_results:
            cves = result.get('cves', {})
            if isinstance(cves, dict):
                count = sum(
                    len(items) for items in cves.values()
                    if isinstance(items, builtins.list)
                )
            elif isinstance(cves, builtins.list):
                count = len(cves)
            else:
                count = 0
            total_cves += count
            domains_with_cves += count > 0

        click.echo(f"Scan completed. Results saved to: {output_path}")
        click.echo(
            f"Targets processed: {len(scanned_results)}; "
            f"targets with CVEs: {domains_with_cves}; CVEs found: {total_cves}"
        )

    except Exception as e:
        click.echo(f"Error during scan: {e}", err=True)

@cli.command()
@click.argument('domain')
@click.pass_context
def scan_one(ctx, domain):
    try:
        orchestrator = ScanOrchestrator(ctx.obj['config'])
        result = asyncio.run(orchestrator.scan_single(domain))

        click.echo("\n" + "="*50)
        click.echo(f"Scan results for: {domain}")
        click.echo("="*50)

        if result.get('error'):
            click.echo(f"Error: {result['error']}")
        else:
            click.echo(f"Status: {result.get('status_code', 'N/A')}")
            if 'final_url' in result and result['final_url'] != domain:
                click.echo(f"Redirected to: {result['final_url']}")

            technologies = result.get('technologies', {})
            if technologies:
                click.echo("\nTechnologies found:")
                for tech_type, tech_list in technologies.items():
                    if tech_list:
                        if tech_type == 'database':
                            click.echo(f"  {tech_type}: {', '.join(tech_list)}")
                        elif tech_type == 'language':
                            click.echo(f"  {tech_type}: {', '.join(tech_list)}")
                        else:
                            click.echo(f"  {tech_type}: {', '.join(tech_list)}")

            cameras = result.get('cameras', [])
            if cameras:
                click.echo(f"\nCameras: {', '.join(cameras)}")

            routers = technologies.get('router', [])
            if routers:
                click.echo(f"\nRouters: {', '.join(routers)}")

            databases = technologies.get('database', [])
            if databases:
                click.echo(f"\nDatabases: {', '.join(databases)}")

            languages = technologies.get('language', [])
            if languages:
                click.echo(f"\nProgramming languages: {', '.join(languages)}")

            plugins = technologies.get('plugins', [])
            if plugins:
                click.echo(f"\nPlugins: {', '.join(plugins)}")

            themes = technologies.get('themes', [])
            if themes:
                click.echo(f"\nThemes: {', '.join(themes)}")

            js_libs = technologies.get('javascript', [])
            if js_libs:
                click.echo(f"\nJavaScript libraries: {', '.join(js_libs)}")

            bitrix_components = technologies.get('bitrix_components', [])
            if bitrix_components:
                click.echo(f"\nBitrix components: {', '.join(bitrix_components)}")

            
            cves = result.get('cves', {})
            if cves:
                click.echo(f"\nCVEs found ({len(cves)} affected technologies):")
                for tech_identifier, cve_list in cves.items():
                    if cve_list:
                        click.echo(f"  {tech_identifier}: {len(cve_list)} CVE(s)")
                        for cve in cve_list[:3]:  
                            cve_id = cve.get('id', 'N/A')
                            severity = cve.get('cvss', {}).get('severity', 'N/A')
                            score = cve.get('cvss', {}).get('score', 'N/A')
                            if not cve.get('version_range_confirmed', False):
                                click.echo(
                                    f"    - {cve_id} (NVD keyword match; exact affected "
                                    f"version not confirmed, "
                                    f"Severity: {severity}, Score: {score})"
                                )
                            else:
                                click.echo(
                                    f"    - {cve_id} (version match; Severity: {severity}, "
                                    f"Score: {score})"
                                )
                        if len(cve_list) > 3:
                            click.echo(f"    ... and {len(cve_list) - 3} more")

            files = result.get('sensitive_files', [])
            if files:
                click.echo(f"\nSensitive files found ({len(files)}):")
                for file_info in files[:5]:
                    click.echo(f"  • {file_info.get('url')}")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)

@cli.command()
@click.argument('db_path')
@click.option('--format', '-f', type=click.Choice(['json', 'csv']), default='json')
def export(db_path, format):
    try:
        from fullmute.db.queries import DBQueries

        init_db(db_path)
        db = DBQueries(db_path)

        def decode_list(value):
            try:
                decoded = json.loads(value or '[]')
            except (TypeError, json.JSONDecodeError):
                return []
            return decoded if isinstance(decoded, builtins.list) else []

        def attach_cve_enrichment(cve):
            cve['references'] = decode_list(cve.pop('references_json', None))
            cve['exploits'] = decode_list(cve.pop('exploits_json', None))
            cve['nuclei_templates'] = decode_list(
                cve.pop('nuclei_templates_json', None)
            )
            exploit_links = []
            for exploit in cve['exploits']:
                if not isinstance(exploit, dict):
                    continue
                exploit_id = exploit.get('exploit_id') or exploit.get('EDB-ID')
                path = exploit.get('path')
                if not exploit_id and isinstance(path, str):
                    path_stem = Path(path.replace('\\', '/')).stem
                    if path_stem.isdigit():
                        exploit_id = path_stem
                url = (
                    exploit.get('edb_url')
                    or exploit.get('exploit_url')
                    or exploit.get('url')
                )
                if not url and exploit_id:
                    url = f"https://www.exploit-db.com/exploits/{exploit_id}"
                if url:
                    exploit_links.append({
                        'cve_id': cve.get('cve_id'),
                        'title': exploit.get('title') or exploit.get('name') or '',
                        'exploit_id': exploit_id,
                        'url': url,
                    })
            cve['exploit_links'] = exploit_links
            return cve

        domains = db.fetch_all_domains()

        detailed_data = []
        for domain_row in domains:
            domain_dict = dict(domain_row)
            domain_id = domain_dict['id']

            with db._get_cursor() as cursor:
                cursor.execute('SELECT * FROM technologies WHERE domain_id = ?', (domain_id,))
                tech_rows = cursor.fetchall()
                technologies = []
                for tech_row in tech_rows:
                    tech_dict = dict(tech_row)
                    tech_id = tech_dict['id']

                    cursor.execute('''
                        SELECT cve_id, description, severity, cvss_score, cvss_version,
                               published_date, last_modified, vector_string, references_json,
                               applicability, exploits_json, nuclei_templates_json
                        FROM cves WHERE technology_id = ?
                    ''', (tech_id,))
                    tech_dict['cves'] = [
                        attach_cve_enrichment(dict(row)) for row in cursor.fetchall()
                    ]

                    technologies.append(tech_dict)

                cursor.execute('SELECT * FROM plugins WHERE domain_id = ?', (domain_id,))
                plugin_rows = cursor.fetchall()
                plugins = []
                for plugin_row in plugin_rows:
                    plugin_dict = dict(plugin_row)
                    plugin_id = plugin_dict['id']

                    cursor.execute('''
                        SELECT cve_id, description, severity, cvss_score, cvss_version,
                               published_date, last_modified, vector_string, references_json,
                               exploits_json, nuclei_templates_json
                        FROM plugin_cves WHERE plugin_id = ?
                    ''', (plugin_id,))
                    plugin_dict['cves'] = [
                        attach_cve_enrichment(dict(row)) for row in cursor.fetchall()
                    ]

                    plugins.append(plugin_dict)

                cursor.execute('SELECT * FROM sensitive_files WHERE domain_id = ?', (domain_id,))
                file_rows = cursor.fetchall()
                sensitive_files = [dict(row) for row in file_rows]

                cursor.execute('''
                    SELECT login_url, username, password, description, detection_reason, found_at
                    FROM default_credentials WHERE domain_id = ?
                ''', (domain_id,))
                default_credentials = [dict(row) for row in cursor.fetchall()]

                cursor.execute('SELECT * FROM port_scans WHERE domain_id = ? ORDER BY scanned_at DESC', (domain_id,))
                port_scan_rows = cursor.fetchall()
                port_scans = []
                for scan_row in port_scan_rows:
                    scan_dict = dict(scan_row)
                    scan_id = scan_dict['id']

                    cursor.execute('SELECT * FROM open_ports WHERE port_scan_id = ? ORDER BY port', (scan_id,))
                    open_port_rows = cursor.fetchall()
                    open_ports = []
                    for port_row in open_port_rows:
                        port_dict = dict(port_row)
                        port_id = port_dict['id']

                        cursor.execute('''
                            SELECT id, cve_id, description, severity, cvss_score, cvss_version,
                                   published_date, last_modified, vector_string,
                                   nuclei_templates_json
                            FROM port_cves WHERE open_port_id = ?
                        ''', (port_id,))
                        port_cve_rows = cursor.fetchall()
                        port_cves = []
                        for cve_row in port_cve_rows:
                            cve_dict = dict(cve_row)
                            cve_id = cve_dict['id']
                            cve_dict['nuclei_templates'] = decode_list(
                                cve_dict.pop('nuclei_templates_json', None)
                            )

                            cursor.execute('''
                                SELECT exploit_title, exploit_path, exploit_type,
                                       platform, date, author
                                FROM port_exploits WHERE port_cve_id = ?
                            ''', (cve_id,))
                            cve_dict['exploits'] = [dict(row) for row in cursor.fetchall()]
                            cve_dict['exploit_links'] = []
                            for exploit in cve_dict['exploits']:
                                exploit_id = Path(
                                    str(exploit.get('exploit_path') or '').replace('\\', '/')
                                ).stem
                                url = (
                                    f"https://www.exploit-db.com/exploits/{exploit_id}"
                                    if exploit_id.isdigit() else None
                                )
                                if url:
                                    cve_dict['exploit_links'].append({
                                        'cve_id': cve_dict.get('cve_id'),
                                        'title': exploit.get('exploit_title') or '',
                                        'exploit_id': exploit_id,
                                        'url': url,
                                    })

                            port_cves.append(cve_dict)

                        port_dict['cves'] = port_cves
                        open_ports.append(port_dict)

                    scan_dict['open_ports'] = open_ports
                    port_scans.append(scan_dict)

            domain_dict['technologies'] = technologies
            domain_dict['plugins'] = plugins
            domain_dict['sensitive_files'] = sensitive_files
            domain_dict['default_credentials'] = default_credentials
            domain_dict['port_scans'] = port_scans
            domain_dict['exploit_links'] = [
                link for technology in technologies
                for cve in technology.get('cves', [])
                for link in cve.get('exploit_links', [])
            ] + [
                link for plugin in plugins
                for cve in plugin.get('cves', [])
                for link in cve.get('exploit_links', [])
            ] + [
                link for scan in port_scans
                for port in scan.get('open_ports', [])
                for cve in port.get('cves', [])
                for link in cve.get('exploit_links', [])
            ]
            domain_dict['nuclei_templates'] = [
                template for technology in technologies
                for cve in technology.get('cves', [])
                for template in cve.get('nuclei_templates', [])
            ] + [
                template for plugin in plugins
                for cve in plugin.get('cves', [])
                for template in cve.get('nuclei_templates', [])
            ] + [
                template for scan in port_scans
                for port in scan.get('open_ports', [])
                for cve in port.get('cves', [])
                for template in cve.get('nuclei_templates', [])
            ]

            detailed_data.append(domain_dict)

        if format == 'json':
            output_file = 'export.json'
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(detailed_data, f, indent=2, ensure_ascii=False, default=str)

            click.echo(f"Exported to {output_file}")
            click.echo(f"  Domains: {len(detailed_data)}")
            click.echo(f"  Technologies: {sum(len(d['technologies']) for d in detailed_data)}")
            click.echo(f"  Plugins: {sum(len(d['plugins']) for d in detailed_data)}")
            click.echo(f"  Sensitive files: {sum(len(d['sensitive_files']) for d in detailed_data)}")
            click.echo(f"  Default credentials: {sum(len(d['default_credentials']) for d in detailed_data)}")
            click.echo(f"  Port scans: {sum(len(d['port_scans']) for d in detailed_data)}")

        elif format == 'csv':
            output_file = 'export.csv'
            import csv
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                if detailed_data:
                    flattened_data = []
                    for item in detailed_data:
                        flat_item = item.copy()

                        tech_names = [f"{t['category']}:{t['name']}" for t in item.get('technologies', [])]
                        plugin_names = [f"{p['plugin_name']}" for p in item.get('plugins', [])]
                        file_paths = [f['file_path'] for f in item.get('sensitive_files', [])]
                        cred_entries = [f"{c['username']}:{c['password']}@{c['login_url']}" for c in item.get('default_credentials', [])]
                        port_entries = []
                        exploit_entries = []
                        nuclei_entries = []
                        for technology in item.get('technologies', []):
                            cves = technology.get('cves', [])
                            for cve in cves:
                                exploit_entries.extend(cve.get('exploit_links', []))
                                nuclei_entries.extend(cve.get('nuclei_templates', []))
                        for plugin in item.get('plugins', []):
                            for cve in plugin.get('cves', []):
                                exploit_entries.extend(cve.get('exploit_links', []))
                                nuclei_entries.extend(cve.get('nuclei_templates', []))
                        for ps in item.get('port_scans', []):
                            for op in ps.get('open_ports', []):
                                port_entries.append(f"{op['port']}/{op['service']}")
                                for cve in op.get('cves', []):
                                    exploit_entries.extend(cve.get('exploit_links', []))
                                    nuclei_entries.extend(cve.get('nuclei_templates', []))

                        flat_item['tech_details'] = '; '.join(tech_names)
                        flat_item['plugin_details'] = '; '.join(plugin_names)
                        flat_item['file_details'] = '; '.join(file_paths)
                        flat_item['credential_details'] = '; '.join(cred_entries)
                        flat_item['port_details'] = '; '.join(port_entries)
                        flat_item['exploit_links'] = '; '.join(
                            f"{item.get('cve_id')}: {item.get('title') or 'Exploit'} - {item.get('url')}"
                            for item in exploit_entries
                        )
                        flat_item['nuclei_templates'] = '; '.join(
                            f"{item.get('cve_id')}: {item.get('template_name') or 'Template not found'} "
                            f"[{item.get('status', 'unknown')}, findings: {item.get('findings_count', 0)}]"
                            for item in nuclei_entries
                        )

                        for key in ['technologies', 'plugins', 'sensitive_files', 'default_credentials', 'port_scans']:
                            if key in flat_item:
                                del flat_item[key]

                        flattened_data.append(flat_item)

                    fieldnames = flattened_data[0].keys() if flattened_data else []
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for item in flattened_data:
                        writer.writerow(item)

            click.echo(f"Exported to {output_file}")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)

@cli.group()
def signatures():
    pass

@signatures.command()
@click.argument('type')
@click.argument('name')
@click.argument('patterns_file', type=click.File('r'))
def add(type, name, patterns_file):
    loader = SignatureLoader()
    try:
        patterns = json.load(patterns_file)
        if loader.add_signature(type, name, patterns):
            click.echo(f"Signature '{name}' added to '{type}'")
        else:
            click.echo("Failed to add signature")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)

@signatures.command()
@click.argument('type')
def list(type):
    loader = SignatureLoader()
    signatures = loader.load(type)

    if not signatures:
        click.echo(f"No signatures found for type '{type}'")
        return

    click.echo(f"\nSignatures for '{type}':")
    click.echo("="*50)

    for name, patterns in signatures.items():
        click.echo(f"\n{name}:")
        for key, value in patterns.items():
            try:
                if isinstance(value, list):
                    click.echo(f"  {key}:")
                    for item in value[:3]:
                        click.echo(f"    - {item}")
                    if len(value) > 3:
                        click.echo(f"    ... and {len(value) - 3} more")
                else:
                    click.echo(f"  {key}: {value}")
            except TypeError:
                
                click.echo(f"  {key}: {str(value)[:100]}...")

@cli.command()
@click.argument('db_path')
def stats(db_path):
    try:
        from fullmute.db.queries import DBQueries

        db = DBQueries(db_path)
        domains = db.fetch_all_domains()

        total = len(domains)
        alive = sum(1 for d in domains if dict(d).get('is_alive'))
        with_cameras = sum(1 for d in domains if dict(d).get('has_camera'))

        click.echo("\n" + "="*50)
        click.echo("SCAN STATISTICS")
        click.echo("="*50)
        click.echo(f"Total domains: {total}")
        if total > 0:
            click.echo(f"Alive: {alive} ({alive/total*100:.1f}%)")
            click.echo(f"With cameras: {with_cameras} ({with_cameras/total*100:.1f}%)")
        else:
            click.echo("Alive: 0 (0.0%)")
            click.echo("With cameras: 0 (0.0%)")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)

if __name__ == "__main__":
    cli()
