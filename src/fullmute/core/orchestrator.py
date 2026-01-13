import asyncio
import yaml
import json
from pathlib import Path
from fullmute.core.scanner import FullMuteScanner
from fullmute.utils.logger import setup_logger
from fullmute.db.engine import init_db

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

    async def scan_from_file(self, domains_file: str, output_file: str = None):
        domains_file = Path(domains_file)
        if not domains_file.exists():
            logger.error(f"Domains file not found: {domains_file}")
            return []

        with open(domains_file, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]

        logger.info(f"Loaded {len(domains)} domains from {domains_file}")

        self.initialize()

        max_concurrent = self.config.get('scanner', {}).get('max_concurrent', 10)
        results = await self.scanner.scan(domains, max_concurrent)

        if output_file:
            self._save_results(results, output_file)

        return results

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
        return await self.scanner.scan_domain(domain)
