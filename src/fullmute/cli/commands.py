import logging
from typing import Any

import click
import json
import asyncio
from pathlib import Path

import yaml

from fullmute.core.orchestrator import ScanOrchestrator
from fullmute.detector.signature_loader import SignatureLoader
from fullmute.db.engine import init_db
from fullmute.utils.logger import setup_logging

logger = logging.getLogger('fullmute')

@click.group()
@click.option('--config', default='config.yaml', help='Path to config file')
@click.pass_context
def cli(ctx, config):
    ctx.ensure_object(dict)
    setup_logging()
    ctx.obj['config'] = _load_config(Path(config))
    logging_config = ctx.obj['config'].get('logging')
    if logging_config:
        setup_logging(
            level=logging_config.get('level', logging.INFO),
            file_path=logging_config.get('file'),
            max_mb=logging_config.get('max_mb', 50),
            backups=logging_config.get('backups', 5))


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
        config = ctx.obj['config']
        orchestrator = ScanOrchestrator(config)

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
        config = ctx.obj['config']
        orchestrator = ScanOrchestrator(config)
        result = asyncio.run(orchestrator.scan_single(domain))

        click.echo("\n" + "="*50)
        click.echo(f"Scan results for: {domain}")
        click.echo("="*50)

        if result.get('error'):
            click.echo(f"Error: {result['error']}")
        else:
            click.echo(f"Status: {result.get('status_code', 'N/A')}")
            # Показываем финальный URL, если он отличается от исходного
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

        # Получаем все домены
        domains = db.fetch_all_domains()

        # Для каждого домена получаем связанную информацию
        detailed_data = []
        for domain_row in domains:
            domain_dict = dict(domain_row)
            domain_id = domain_dict['id']

            # Получаем технологии для этого домена
            with db._get_cursor() as cursor:
                cursor.execute('SELECT * FROM technologies WHERE domain_id = ?', (domain_id,))
                tech_rows = cursor.fetchall()
                technologies = [dict(row) for row in tech_rows]

                # Получаем плагины для этого домена
                cursor.execute('SELECT * FROM plugins WHERE domain_id = ?', (domain_id,))
                plugin_rows = cursor.fetchall()
                plugins = [dict(row) for row in plugin_rows]

                # Получаем чувствительные файлы для этого домена
                cursor.execute('SELECT * FROM sensitive_files WHERE domain_id = ?', (domain_id,))
                file_rows = cursor.fetchall()
                sensitive_files = [dict(row) for row in file_rows]

            # Добавляем информацию о технологиях в словарь домена
            domain_dict['technologies'] = technologies
            domain_dict['plugins'] = plugins
            domain_dict['sensitive_files'] = sensitive_files

            detailed_data.append(domain_dict)

        if format == 'json':
            output_file = 'export.json'
            with open(output_file, 'w') as f:
                json.dump(detailed_data, f, indent=2)

            click.echo(f"Exported to {output_file}")

        elif format == 'csv':
            output_file = 'export.csv'
            import csv
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                if detailed_data:
                    # Для CSV формата мы будем использовать flattened структуру
                    flattened_data = []
                    for item in detailed_data:
                        flat_item = item.copy()

                        # Преобразуем списки в строки для CSV
                        tech_names = [f"{t['category']}:{t['name']}" for t in item.get('technologies', [])]
                        flat_item['technologies'] = '; '.join(tech_names)

                        plugin_names = [f"{p['plugin_name']}" for p in item.get('plugins', [])]
                        flat_item['plugins'] = '; '.join(plugin_names)

                        file_paths = [f['file_path'] for f in item.get('sensitive_files', [])]
                        flat_item['sensitive_files'] = '; '.join(file_paths)

                        # Удаляем вложенные структуры, которые не подходят для CSV
                        del flat_item['technologies']  # временно удаляем, чтобы заменить ниже
                        flat_item['tech_details'] = '; '.join(tech_names)
                        flat_item['plugin_details'] = '; '.join(plugin_names)
                        flat_item['file_details'] = '; '.join(file_paths)

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


def _load_config(config_path: Path) -> dict[str, Any]:
    if not config_path.exists():
        logger.warning(f"Config file not found at {config_path}, using defaults")
        return {}

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return {}


if __name__ == "__main__":
    cli()
