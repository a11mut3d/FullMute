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
                        click.echo(f"  {tech_type}: {', '.join(tech_list)}")

            cameras = result.get('cameras', [])
            if cameras:
                click.echo(f"\nCameras: {', '.join(cameras)}")

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
            if isinstance(value, list):
                click.echo(f"  {key}:")
                for item in value[:3]:
                    click.echo(f"    - {item}")
                if len(value) > 3:
                    click.echo(f"    ... and {len(value) - 3} more")
            else:
                click.echo(f"  {key}: {value}")

@cli.command()
@click.argument('db_path')
def stats(db_path):
    try:
        from fullmute.db.queries import DBQueries

        db = DBQueries(db_path)
        domains = db.fetch_all_domains()

        total = len(domains)
        alive = sum(1 for d in domains if d.get('is_alive'))
        with_cameras = sum(1 for d in domains if d.get('has_camera'))

        click.echo("\n" + "="*50)
        click.echo("SCAN STATISTICS")
        click.echo("="*50)
        click.echo(f"Total domains: {total}")
        click.echo(f"Alive: {alive} ({alive/total*100:.1f}%)")
        click.echo(f"With cameras: {with_cameras} ({with_cameras/total*100:.1f}%)")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)

if __name__ == "__main__":
    cli()
