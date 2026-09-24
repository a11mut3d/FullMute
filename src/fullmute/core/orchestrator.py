import asyncio
import yaml
import json
import time
from pathlib import Path
from fullmute.core.scanner import FullMuteScanner
from fullmute.scanner.port_scanner import PortScanner, TOP_20_PORTS
from fullmute.utils.searchsploit import search_sploit_batch
from fullmute.utils.nuclei import NucleiRunner
from fullmute.utils.logger import setup_logger
from fullmute.db.engine import init_db
from fullmute.db.queries import DBQueries

logger = setup_logger()

class ScanOrchestrator:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.scanner = None

    def _load_config(self):
        if not self.config_path.exists():
            logger.warning(f"Config file not found at {self.config_path}, using defaults")
            return {}

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}

    def initialize(self):
        db_path = self.config.get('database', {}).get('path', 'fullmute.db')

        try:
            init_db(db_path)
            logger.info(f"Database initialized at {db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

        scanner_config = self.config.get('scanner', {})
        self.scanner = FullMuteScanner(db_path, scanner_config)
        logger.info("Scanner initialized")

    async def scan_from_file(self, domains_file: str, output_file: str = None,
                             full: bool = False):
        domains_file = Path(domains_file)
        if not domains_file.exists():
            logger.error(f"Domains file not found: {domains_file}")
            return []

        with open(domains_file, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]

        logger.info(f"Loaded {len(domains)} domains from {domains_file}")

        if full:
            scanner_config = self.config.setdefault('scanner', {})
            scanner_config.update({
                'nuclei_enabled': True,
                'search_exploits': True,
                'test_default_credentials': True,
            })

        self.initialize()
        try:
            max_concurrent = self.config.get('scanner', {}).get('max_concurrent', 10)
            if full:
                results = await self._scan_full(domains, max_concurrent)
            else:
                results = await self.scanner.scan(domains, max_concurrent)

            if output_file:
                self._save_results(results, output_file)

            return results
        finally:
            try:
                await self.scanner.close()
            except Exception:
                pass

    async def _scan_full(self, domains, max_concurrent):
        results = await self.scanner.scan(domains, max_concurrent)
        scanner_config = self.config.get('scanner', {})
        nvd_api_key = scanner_config.get('nvd_api_key')
        db = DBQueries(self.config.get('database', {}).get('path', 'fullmute.db'))
        try:
            concurrency = max(1, int(max_concurrent))
        except (TypeError, ValueError):
            concurrency = 1
        semaphore = asyncio.Semaphore(concurrency)

        async def enrich(result):
            domain = result.get('domain')
            if not domain or result.get('error'):
                return result

            cves = result.get('cves', {})
            cve_ids = []
            if isinstance(cves, dict):
                for items in cves.values():
                    if not isinstance(items, list):
                        continue
                    cve_ids.extend(
                        cve.get('id') or cve.get('cve_id')
                        for cve in items
                        if isinstance(cve, dict) and (cve.get('id') or cve.get('cve_id'))
                    )
            if cve_ids:
                result['exploits'] = await asyncio.get_running_loop().run_in_executor(
                    None, search_sploit_batch, list(dict.fromkeys(cve_ids))
                )

            async with semaphore:
                started = time.monotonic()
                port_results = await PortScanner(
                    timeout=float(scanner_config.get('port_scan', {}).get('timeout', 5.0)),
                    max_concurrent=10,
                ).scan_with_cves(
                    domain,
                    ports=scanner_config.get('port_scan', {}).get('ports', TOP_20_PORTS),
                    nvd_api_key=nvd_api_key,
                    search_exploits=True,
                    test_default_credentials=True,
                )

            result['open_ports'] = []
            for port_result in port_results:
                port_data = {
                    'port': port_result.port,
                    'protocol': port_result.protocol,
                    'state': port_result.state,
                    'service': port_result.service,
                    'version': port_result.version,
                    'product': port_result.product,
                    'banner': port_result.banner or '',
                    'ssl': port_result.ssl,
                    'cves': port_result.cves or [],
                    'exploits': port_result.exploits or [],
                }
                result['open_ports'].append(port_data)

            result['port_scan_count'] = len(result['open_ports'])
            result['port_cves_count'] = sum(
                len(port.get('cves', [])) for port in result['open_ports']
            )
            result['port_exploits_count'] = sum(
                sum(len(item.get('exploits', [])) for item in port.get('exploits', [])
                    if isinstance(item, dict))
                for port in result['open_ports']
            )
            port_cve_ids = list(dict.fromkeys(
                cve.get('id') or cve.get('cve_id')
                for port in result['open_ports']
                for cve in port.get('cves', [])
                if isinstance(cve, dict) and (cve.get('id') or cve.get('cve_id'))
            ))
            if port_cve_ids:
                nuclei = NucleiRunner(
                    binary=scanner_config.get('nuclei_binary', 'nuclei'),
                    templates_path=scanner_config.get(
                        'nuclei_templates_path', './nuclei-templates'
                    ),
                    timeout=scanner_config.get('nuclei_timeout', 120),
                )
                result['nuclei'] = result.get('nuclei', []) + await nuclei.run_for_cves(
                    result.get('final_url') or domain,
                    port_cve_ids,
                )
            self._save_port_results(db, domain, result['open_ports'], started)
            return result

        return await asyncio.gather(*(enrich(result) for result in results))

    def _save_port_results(self, db, domain, ports, started):
        domain_id = db.get_domain_id(domain)
        if not domain_id:
            return
        port_scan_id = db.add_port_scan({
            'domain_id': domain_id,
            'total_ports_scanned': len(TOP_20_PORTS),
            'open_ports_count': len(ports),
            'scan_duration': time.monotonic() - started,
        })
        if not port_scan_id:
            return
        for port in ports:
            open_port_id = db.add_open_port({
                **port,
                'port_scan_id': port_scan_id,
                'cves_count': len(port.get('cves', [])),
                'exploits_count': sum(
                    len(item.get('exploits', []))
                    for item in port.get('exploits', [])
                    if isinstance(item, dict)
                ),
            })
            if not open_port_id:
                continue
            for cve in port.get('cves', []):
                cve_id = cve.get('cve_id') or cve.get('id')
                port_cve_id = db.add_port_cve({
                    **cve,
                    'open_port_id': open_port_id,
                    'cve_id': cve_id,
                    'severity': cve.get('severity') or cve.get('cvss', {}).get('severity'),
                    'cvss_score': cve.get('cvss_score') or cve.get('cvss', {}).get('score'),
                    'vector_string': cve.get('vector_string') or cve.get('cvss', {}).get('vector'),
                })
                if not port_cve_id:
                    continue
                for exploit_group in port.get('exploits', []):
                    if not isinstance(exploit_group, dict) or exploit_group.get('cve_id') != cve_id:
                        continue
                    for exploit in exploit_group.get('exploits', []):
                        db.add_port_exploit({
                            'port_cve_id': port_cve_id,
                            'exploit_title': exploit.get('title', ''),
                            'exploit_path': exploit.get('path', ''),
                            'exploit_type': exploit.get('type', ''),
                            'platform': exploit.get('platform', ''),
                            'date': exploit.get('date', ''),
                            'author': exploit.get('author', ''),
                        })

    def _save_results(self, results, output_file: str):
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        json_results = []
        for result in results:
            if isinstance(result, Exception):
                continue
            json_result = {}
            for key, value in result.items():
                json_result[key] = value
            json_results.append(json_result)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_results, f, indent=2, ensure_ascii=False)

        logger.info(f"Results saved to {output_file}")

    async def scan_single(self, domain: str):
        self.initialize()
        try:
            return await self.scanner.scan_domain(domain)
        finally:
            try:
                await self.scanner.close()
            except Exception:
                pass
