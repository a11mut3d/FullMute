import asyncio
import yaml
import json
import time
from pathlib import Path
from fullmute.core.scanner import FullMuteScanner
from fullmute.scanner.port_scanner import PortScanner, TOP_20_PORTS
from fullmute.utils.nuclei import NucleiRunner
from fullmute.utils.logger import setup_logger
from fullmute.db.engine import init_db
from fullmute.db.queries import DBQueries

logger = setup_logger()

class ScanOrchestrator:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path).expanduser().resolve()
        self.config = self._load_config()
        self.scanner = None

    def _database_path(self) -> Path:
        configured_path = Path(
            self.config.get('database', {}).get('path', 'fullmute.db')
        ).expanduser()
        if not configured_path.is_absolute():
            configured_path = self.config_path.parent / configured_path
        return configured_path.resolve()

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
        db_path = self._database_path()

        try:
            init_db(str(db_path))
            logger.info(f"Database initialized at {db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

        scanner_config = self.config.get('scanner', {})
        self.scanner = FullMuteScanner(str(db_path), scanner_config)
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
        db = DBQueries(str(self._database_path()))
        try:
            concurrency = max(1, int(max_concurrent))
        except (TypeError, ValueError):
            concurrency = 1
        semaphore = asyncio.Semaphore(concurrency)

        async def enrich(result):
            domain = result.get('domain')
            if not domain or result.get('error'):
                return result

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
            self._save_port_results(
                db,
                domain,
                result['open_ports'],
                started,
                result.get('nuclei', []),
            )
            return result

        return await asyncio.gather(*(enrich(result) for result in results))

    def _save_port_results(self, db, domain, ports, started, nuclei_results=None):
        domain_id = db.get_domain_id(domain)
        if not domain_id:
            return
        nuclei_by_cve = {}
        for item in nuclei_results or []:
            if not isinstance(item, dict) or not item.get('cve_id'):
                continue
            template = item.get('template')
            nuclei_by_cve.setdefault(item['cve_id'], []).append({
                'cve_id': item.get('cve_id'),
                'template_name': item.get('template_name') or (
                    Path(str(template).replace('\\', '/')).name if template else None
                ),
                'template': template,
                'status': item.get('status', 'unknown'),
                'findings_count': len(item.get('findings', []))
                if isinstance(item.get('findings'), list) else 0,
            })
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
                    'nuclei_templates': nuclei_by_cve.get(cve_id, []),
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
            json_result = dict(result)
            exploit_links = self._collect_exploit_links(json_result)
            if exploit_links:
                json_result['exploit_links'] = exploit_links
            nuclei_results = json_result.get('nuclei', [])
            if not isinstance(nuclei_results, list):
                nuclei_results = []
            json_result['nuclei_templates'] = [
                {
                    'cve_id': item.get('cve_id'),
                    'template_name': item.get('template_name') or Path(
                        str(item.get('template', ''))
                    ).name or None,
                    'status': item.get('status', 'unknown'),
                    'findings_count': len(item.get('findings', []))
                    if isinstance(item.get('findings'), list) else 0,
                }
                for item in nuclei_results
                if isinstance(item, dict)
            ]
            json_results.append(json_result)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_results, f, indent=2, ensure_ascii=False)

        logger.info(f"Results saved to {output_file}")

    @staticmethod
    def _collect_exploit_links(result):
        links = []
        seen = set()

        def add_exploit(exploit, cve_id=None):
            if not isinstance(exploit, dict):
                return
            exploit_id = exploit.get('exploit_id') or exploit.get('EDB-ID')
            url = (
                exploit.get('edb_url')
                or exploit.get('exploit_url')
                or exploit.get('url')
            )
            if not url and exploit_id:
                url = f"https://www.exploit-db.com/exploits/{exploit_id}"
            if not url and isinstance(exploit.get('path'), str):
                url = exploit['path'] if exploit['path'].startswith(('http://', 'https://')) else None
            if not url:
                return
            link_cve = exploit.get('cve_id') or cve_id
            key = (str(link_cve or ''), str(url))
            if key in seen:
                return
            seen.add(key)
            links.append({
                'cve_id': link_cve,
                'title': exploit.get('title') or exploit.get('name') or '',
                'exploit_id': exploit_id,
                'url': url,
            })

        def add_exploit_collection(collection, cve_id=None):
            if isinstance(collection, dict):
                for key, value in collection.items():
                    add_exploit_collection(value, key if str(key).startswith('CVE-') else cve_id)
            elif isinstance(collection, list):
                for item in collection:
                    if isinstance(item, dict) and isinstance(item.get('exploits'), list):
                        add_exploit_collection(item['exploits'], item.get('cve_id') or cve_id)
                    else:
                        add_exploit(item, cve_id)

        add_exploit_collection(result.get('exploits'))
        cves = result.get('cves', [])
        if isinstance(cves, dict):
            add_exploit_collection(cves)
        else:
            add_exploit_collection([
                cve for cve in cves
                if isinstance(cve, dict) and cve.get('exploits')
            ] if isinstance(cves, list) else [])
        for port in result.get('open_ports', []) if isinstance(result.get('open_ports'), list) else []:
            if isinstance(port, dict):
                add_exploit_collection(port.get('exploits'))
        return links

    async def scan_single(self, domain: str):
        self.initialize()
        try:
            return await self.scanner.scan_domain(domain)
        finally:
            try:
                await self.scanner.close()
            except Exception:
                pass
