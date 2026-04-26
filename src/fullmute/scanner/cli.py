import click
import asyncio
import json
from datetime import datetime
from fullmute.scanner.port_scanner import (
    PortScanner, 
    scan_ports, 
    scan_ports_with_cves,
    TOP_20_PORTS
)
from fullmute.db.engine import init_db
from fullmute.db.queries import DBQueries
from fullmute.utils.logger import setup_logger

logger = setup_logger()


@click.group()
def port():
    pass


@port.command()
@click.argument('host')
@click.option('--ports', '-p', default='', help='Comma-separated list of ports (default: top 20)')
@click.option('--timeout', '-t', default=5.0, help='Connection timeout')
@click.option('--output', '-o', default=None, help='Output to JSON file')
@click.option('--with-cves', is_flag=True, help='Search for CVEs')
@click.option('--with-exploits', is_flag=True, help='Search for exploits (requires --with-cves)')
@click.option('--nvd-api-key', '-k', default=None, help='NVD API key for CVE lookup')
def scan(host, ports, timeout, output, with_cves, with_exploits, nvd_api_key):
    try:
        
        if ports:
            port_list = [int(p.strip()) for p in ports.split(',')]
        else:
            port_list = TOP_20_PORTS
        
        click.echo(f"\n{'='*60}")
        click.echo(f"FullMute Port Scanner")
        click.echo(f"{'='*60}")
        click.echo(f"Target: {host}")
        click.echo(f"Ports: {len(port_list)} ({', '.join(map(str, port_list[:10]))}{'...' if len(port_list) > 10 else ''})")
        click.echo(f"Timeout: {timeout}s")
        click.echo(f"CVE Lookup: {'Yes' if with_cves else 'No'}")
        click.echo(f"Exploit Search: {'Yes' if with_exploits else 'No'}")
        click.echo(f"{'='*60}\n")
        
        
        scanner = PortScanner(timeout=timeout, max_concurrent=10)
        
        if with_cves:
            click.echo("[*] Scanning ports with CVE lookup...")
            results = asyncio.run(
                scanner.scan_with_cves(
                    host, 
                    port_list,
                    nvd_api_key=nvd_api_key,
                    search_exploits=with_exploits
                )
            )
        else:
            click.echo("[*] Scanning ports...")
            results = asyncio.run(scanner.scan_host(host, port_list))
        
        
        click.echo(f"\n{'='*60}")
        click.echo(f"Scan Results")
        click.echo(f"{'='*60}\n")
        
        if not results:
            click.echo("No open ports found.")
        else:
            click.echo(f"Found {len(results)} open port(s):\n")
            
            for port_result in results:
                ssl_marker = " [SSL]" if port_result.ssl else ""
                click.echo(f"  Port {port_result.port}/{port_result.protocol}{ssl_marker}")
                click.echo(f"    Service: {port_result.service}")
                
                if port_result.version:
                    click.echo(f"    Version: {port_result.version}")
                
                if port_result.product:
                    click.echo(f"    Product: {port_result.product}")
                
                if port_result.banner:
                    banner_preview = port_result.banner[:150].replace('\n', ' ')
                    click.echo(f"    Banner: {banner_preview}...")
                
                if port_result.cves:
                    click.echo(f"    CVEs: {len(port_result.cves)}")
                    for cve in port_result.cves[:3]:
                        severity = cve.get('cvss', {}).get('severity', 'N/A')
                        score = cve.get('cvss', {}).get('score', 'N/A')
                        click.echo(f"      - {cve.get('id')} (Severity: {severity}, Score: {score})")
                    if len(port_result.cves) > 3:
                        click.echo(f"      ... and {len(port_result.cves) - 3} more")
                
                if port_result.exploits:
                    click.echo(f"    Exploits: {len(port_result.exploits)}")
                    for exploit in port_result.exploits[:3]:
                        click.echo(f"      - {exploit.get('cve_id')}: {len(exploit.get('exploits', []))} exploit(s)")
                
                click.echo()
        
        
        if output:
            from dataclasses import asdict
            output_data = {
                'scan_time': datetime.now().isoformat(),
                'target': host,
                'ports_scanned': len(port_list),
                'open_ports_count': len(results),
                'results': [asdict(r) for r in results]
            }
            
            with open(output, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            click.echo(f"Results saved to: {output}")
        
        click.echo(f"\n{'='*60}\n")
        
    except KeyboardInterrupt:
        click.echo("\n\nScan interrupted by user")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        logger.error(f"Port scan error: {e}")


@port.command()
@click.argument('host')
@click.option('--ports', '-p', default='', help='Comma-separated list of ports')
@click.option('--timeout', '-t', default=3.0, help='Connection timeout')
def quick(host, ports, timeout):
    try:
        
        quick_ports = [22, 80, 443, 21, 25, 3306, 3389, 5432, 8080, 445]
        
        if ports:
            port_list = [int(p.strip()) for p in ports.split(',')]
        else:
            port_list = quick_ports
        
        click.echo(f"\n[*] Quick scanning {host} ({len(port_list)} ports)...\n")
        
        scanner = PortScanner(timeout=timeout, max_concurrent=20)
        results = asyncio.run(scanner.scan_host(host, port_list, grab_banner=False))
        
        if results:
            click.echo(f"Open ports found:")
            for port_result in results:
                ssl_marker = " [SSL]" if port_result.ssl else ""
                click.echo(f"  {port_result.port}/{port_result.protocol}{ssl_marker} - {port_result.service}")
        else:
            click.echo("No open ports found.")
        
        click.echo()
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@port.command()
@click.argument('db_path')
@click.argument('target')
@click.option('--with-cves', is_flag=True, help='Search for CVEs')
@click.option('--with-exploits', is_flag=True, help='Search for exploits')
@click.option('--nvd-api-key', '-k', default=None, help='NVD API key')
@click.pass_context
def save(ctx, db_path, target, with_cves, with_exploits, nvd_api_key):
    try:
        
        init_db(db_path)
        db = DBQueries(db_path)
        
        click.echo(f"\n[*] Scanning {target} and saving to {db_path}...\n")
        
        
        domain_id = db.get_domain_id(target)
        if not domain_id:
            domain_data = {
                'domain': target,
                'is_alive': True,
                'http_status': 0
            }
            db.add_domain(domain_data)
            domain_id = db.get_domain_id(target)
        
        
        scanner = PortScanner(timeout=5.0, max_concurrent=10)
        
        if with_cves:
            results = asyncio.run(
                scanner.scan_with_cves(
                    target,
                    TOP_20_PORTS,
                    nvd_api_key=nvd_api_key,
                    search_exploits=with_exploits
                )
            )
        else:
            results = asyncio.run(scanner.scan_host(target, TOP_20_PORTS))
        
        if not results:
            click.echo("No open ports found.")
            return
        
        
        import time
        start_time = time.time()
        
        scan_data = {
            'domain_id': domain_id,
            'total_ports_scanned': len(TOP_20_PORTS),
            'open_ports_count': len(results),
            'scan_duration': time.time() - start_time
        }
        port_scan_id = db.add_port_scan(scan_data)
        
        if not port_scan_id:
            click.echo("Failed to create scan record.")
            return
        
        
        click.echo(f"\nSaving {len(results)} open ports to database...")

        saved_count = 0
        for port_result in results:
            
            if not port_result.banner or not port_result.banner.strip():
                logger.debug(f"Skipping port {port_result.port}: no banner")
                continue

            from dataclasses import asdict
            port_dict = asdict(port_result)
            port_dict['port_scan_id'] = port_scan_id

            open_port_id = db.add_open_port(port_dict)

            if not open_port_id:
                continue

            saved_count += 1

            
            if port_result.cves:
                for cve in port_result.cves:
                    cve_data = {
                        'open_port_id': open_port_id,
                        **cve
                    }
                    port_cve_id = db.add_port_cve(cve_data)
                    
                    
                    if with_exploits and port_result.exploits:
                        for exploit in port_result.exploits:
                            for expl in exploit.get('exploits', []):
                                exploit_data = {
                                    'port_cve_id': port_cve_id,
                                    'exploit_title': expl.get('title', ''),
                                    'exploit_path': expl.get('path', ''),
                                    'exploit_type': expl.get('type', ''),
                                    'platform': expl.get('platform', ''),
                                    'date': expl.get('date', ''),
                                    'author': expl.get('author', '')
                                }
                                db.add_port_exploit(exploit_data)
        
        click.echo(f"Scan saved successfully!")
        click.echo(f"  Open ports with banners: {saved_count}")
        click.echo(f"  Total CVEs: {sum(len(r.cves) for r in results)}")
        click.echo(f"  Total Exploits: {sum(len(r.exploits) for r in results)}\n")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        logger.error(f"Port scan save error: {e}")
