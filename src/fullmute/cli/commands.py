import click
import json
import asyncio
from pathlib import Path
from fullmute.core.orchestrator import ScanOrchestrator
from fullmute.detector.signature_loader import SignatureLoader
from fullmute.db.engine import init_db
from fullmute.utils.logger import setup_logger

logger = setup_logger()

@click.group()
@click.option('--config', default='config.yaml', help='Path to config file')
@click.pass_context
def cli(ctx, config):
    ctx.ensure_object(dict)
    ctx.obj['config'] = config

@cli.command()
@click.argument('db_path')
def init(db_path):
    try:
        init_db(db_path)
        click.echo(f"Database initialized at {db_path}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.argument('db_path')
@click.option('--search-type', '-t', type=click.Choice(['cve', 'cms', 'plugin', 'technology', 'domain', 'server', 'database', 'language']), required=True, help='Type of search')
@click.option('--query', '-q', required=True, help='Search query')
def search(db_path, search_type, query):
    """Search in the database by different criteria"""
    try:
        from fullmute.db.queries import DBQueries
        db = DBQueries(db_path)

        results = []

        if search_type == 'cve':
            
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
@click.pass_context
def scan(ctx, domains_file, output, max_concurrent, timeout, proxy, delay_min, delay_max):
    domains_file = Path(domains_file)
    if not domains_file.exists():
        click.echo(f"Error: File {domains_file} not found", err=True)
        return

    try:
        orchestrator = ScanOrchestrator(ctx.obj['config'])

        config = orchestrator.config
        config['scanner']['max_concurrent'] = max_concurrent
        config['scanner']['timeout'] = timeout
        config['scanner']['proxy_enabled'] = proxy
        config['scanner']['min_delay'] = delay_min
        config['scanner']['max_delay'] = delay_max

        results = asyncio.run(orchestrator.scan_from_file(
            str(domains_file),
            output_file=output
        ))

        click.echo(f"Scan completed! Results saved to: {output}")

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
                            click.echo(f"    - {cve_id} (Severity: {severity}, Score: {score})")
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

        db = DBQueries(db_path)
        domains = db.fetch_all_domains()

        if format == 'json':
            output_file = 'export.json'
            data = []
            for domain in domains:
                domain_dict = dict(domain)
                data.append(domain_dict)

            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)

            click.echo(f"Exported to {output_file}")

        elif format == 'csv':
            output_file = 'export.csv'
            import csv
            with open(output_file, 'w', newline='') as f:
                if domains:
                    writer = csv.DictWriter(f, fieldnames=domains[0].keys())
                    writer.writeheader()
                    for domain in domains:
                        writer.writerow(dict(domain))

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
