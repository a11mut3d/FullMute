import asyncio
import aiohttp
from typing import List, Dict, Any
from fullmute.detector.signature_loader import SignatureLoader
from fullmute.detector.tech_detector import TechDetector
from fullmute.core.verifier import SensitiveFileVerifier
from fullmute.db.queries import DBQueries
from fullmute.utils.http_client import HttpClient
from fullmute.utils.logger import setup_logger
from fullmute.utils.stealth import Stealth
from fullmute.utils.cve_checker import CVEChecker

logger = setup_logger()

class FullMuteScanner:
    def __init__(self, db_path: str, config: Dict[str, Any] = None):
        self.db_path = db_path
        self.config = config or {}

        self.db = DBQueries(db_path)
        self.signature_loader = SignatureLoader()
        self.signatures = self.signature_loader.load_all()

        self.http_client = HttpClient(
            max_retries=self.config.get('max_retries', 3),
            timeout=self.config.get('timeout', 15),
            proxy_enabled=self.config.get('proxy_enabled', False),
            proxy_file=self.config.get('proxy_file')
        )

        self.verifier = SensitiveFileVerifier(
            self.signatures.get('sensitive_files', {})
        )

        self.stealth = Stealth(
            min_delay=self.config.get('min_delay', 1.0),
            max_delay=self.config.get('max_delay', 3.0),
            rotate_user_agents=self.config.get('rotate_user_agents', True)
        )

        
        self.cve_checker = CVEChecker()

        self.stats = {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'with_technologies': 0,
            'with_files': 0,
            'with_cameras': 0,
            'with_cves': 0
        }

    async def scan_domain(self, domain: str):
        self.stats['total'] += 1

        results = {
            "domain": domain,
            "technologies": {},
            "cameras": [],
            "sensitive_files": [],
            "cves": {},
            "error": None,
            "status_code": 0
        }

        try:
            url = f"http://{domain}" if not domain.startswith("http") else domain

            html, headers_dict, cookies_dict, status_code = await self.http_client.fetch(url)
            results["status_code"] = status_code

            if html is None:
                results["error"] = "Failed to fetch site data"
                self.stats['failed'] += 1
                return results

            self.stats['successful'] += 1

            tech_detector = TechDetector(
                url=url,
                headers=headers_dict,
                html=html,
                cookies=cookies_dict,
                signatures=self.signatures
            )

            technologies = tech_detector.detect()
            results["technologies"] = technologies

            if any(tech_list for tech_list in technologies.values()):
                self.stats['with_technologies'] += 1

            cameras = technologies.get('camera', [])
            results["cameras"] = cameras

            if cameras:
                self.stats['with_cameras'] += 1

            routers = technologies.get('router', [])
            if routers:
                self.stats['with_technologies'] += 1

            js_libs = technologies.get('javascript', [])
            if js_libs:
                self.stats['with_technologies'] += 1

            
            tech_with_versions = []
            for tech_type, tech_list in technologies.items():
                for tech in tech_list:
                    
                    if ' (' in tech and tech.endswith(')'):
                        parts = tech.rsplit(' (', 1)
                        if len(parts) == 2:
                            name = parts[0]
                            version = parts[1][:-1]  
                            tech_with_versions.append((name, version))

            
            if 'plugins' in technologies:
                for plugin in technologies['plugins']:
                    if ' (' in plugin and plugin.endswith(')'):
                        parts = plugin.rsplit(' (', 1)
                        if len(parts) == 2:
                            name = parts[0]
                            version = parts[1][:-1]  
                            tech_with_versions.append((name, version))

            if 'themes' in technologies:
                for theme in technologies['themes']:
                    if ' (' in theme and theme.endswith(')'):
                        parts = theme.rsplit(' (', 1)
                        if len(parts) == 2:
                            name = parts[0]
                            version = parts[1][:-1]  
                            tech_with_versions.append((name, version))

            
            if tech_with_versions:
                cve_results = await self.cve_checker.check_cves_batch(tech_with_versions)
                results["cves"] = cve_results

                if cve_results:
                    self.stats['with_cves'] += 1
                    logger.info(f"Found CVEs for {domain}: {len(cve_results)} technology(s) affected")

            async with aiohttp.ClientSession() as session:
                sensitive_files = await self.verifier.verify(session, url)
                results["sensitive_files"] = sensitive_files

                if sensitive_files:
                    self.stats['with_files'] += 1

            self._save_to_db(domain, results)

            logger.info(f"Scanned {domain} - Tech: {len(technologies.get('cms', []))} CMS, CVEs: {len(results['cves'])}, Files: {len(sensitive_files)}")

        except Exception as e:
            logger.error(f"Error scanning {domain}: {e}")
            results["error"] = str(e)
            self.stats['failed'] += 1

        return results

    def _save_to_db(self, domain: str, results: Dict[str, Any]):
        try:
            domain_data = {
                'domain': domain,
                'has_camera': len(results.get('cameras', [])) > 0,
                'is_alive': results.get('error') is None,
                'http_status': results.get('status_code', 0)
            }

            self.db.add_domain(domain_data)

            domain_id = self.db.get_domain_id(domain)

            if domain_id:
                
                technology_ids = {}
                for tech_type, tech_list in results.get('technologies', {}).items():
                    for tech in tech_list:
                        
                        name = tech
                        version = ""

                        if ' (' in tech and tech.endswith(')'):
                            parts = tech.rsplit(' (', 1)
                            if len(parts) == 2:
                                name = parts[0]
                                version = parts[1][:-1]  

                        tech_data = {
                            'domain_id': domain_id,
                            'category': tech_type,
                            'name': name,
                            'version': version,
                            'confidence': 100
                        }
                        tech_id = self.db.add_technology(tech_data)
                        if tech_id:
                            technology_ids[f"{name}_{version}"] = tech_id

                
                plugins = results.get('technologies', {}).get('plugins', [])
                themes = results.get('technologies', {}).get('themes', [])

                plugin_ids = {}

                
                for plugin in plugins:
                    if ' (' in plugin and plugin.endswith(')'):
                        parts = plugin.rsplit(' (', 1)
                        if len(parts) == 2:
                            name = parts[0]
                            version = parts[1][:-1]  

                            
                            cms_type = 'unknown'
                            if any(word in name.lower() for word in ['wp-', 'wordpress']):
                                cms_type = 'wordpress'
                            elif any(word in name.lower() for word in ['joomla', 'com_']):
                                cms_type = 'joomla'
                            elif any(word in name.lower() for word in ['drupal']):
                                cms_type = 'drupal'
                            else:
                                
                                cms_type = 'wordpress'

                            plugin_data = {
                                'domain_id': domain_id,
                                'cms_type': cms_type,
                                'plugin_name': name,
                                'version': version,
                                'status': 'active'
                            }
                            plugin_id = self.db.add_plugin(plugin_data)
                            if plugin_id:
                                plugin_ids[f"{name}_{version}"] = plugin_id

                
                for theme in themes:
                    if ' (' in theme and theme.endswith(')'):
                        parts = theme.rsplit(' (', 1)
                        if len(parts) == 2:
                            name = parts[0]
                            version = parts[1][:-1]  

                            
                            cms_type = 'wordpress_theme'
                            if 'joomla' in name.lower():
                                cms_type = 'joomla_template'
                            elif 'drupal' in name.lower():
                                cms_type = 'drupal_theme'

                            plugin_data = {
                                'domain_id': domain_id,
                                'cms_type': cms_type,
                                'plugin_name': name,
                                'version': version,
                                'status': 'active'
                            }
                            plugin_id = self.db.add_plugin(plugin_data)
                            if plugin_id:
                                plugin_ids[f"{name}_{version}"] = plugin_id

                
                cve_results = results.get('cves', {})
                for tech_identifier, cves in cve_results.items():
                    
                    if ' (' in tech_identifier and tech_identifier.endswith(')'):
                        parts = tech_identifier.rsplit(' (', 1)
                        if len(parts) == 2:
                            name = parts[0]
                            version = parts[1][:-1]  

                            
                            tech_id_key = f"{name}_{version}"
                            tech_id = technology_ids.get(tech_id_key)
                            plugin_id = plugin_ids.get(tech_id_key)

                            if tech_id:
                                for cve in cves:
                                    cve_data = {
                                        'technology_id': tech_id,
                                        'cve_id': cve.get('id'),
                                        'description': cve.get('description'),
                                        'severity': cve.get('cvss', {}).get('severity'),
                                        'cvss_score': cve.get('cvss', {}).get('score'),
                                        'cvss_version': cve.get('cvss', {}).get('version'),
                                        'published_date': cve.get('published_date'),
                                        'last_modified': cve.get('last_modified'),
                                        'vector_string': cve.get('cvss', {}).get('vector'),
                                        'references': cve.get('references', [])
                                    }
                                    self.db.add_cve(cve_data)
                            elif plugin_id:
                                for cve in cves:
                                    plugin_cve_data = {
                                        'plugin_id': plugin_id,
                                        'cve_id': cve.get('id'),
                                        'description': cve.get('description'),
                                        'severity': cve.get('cvss', {}).get('severity'),
                                        'cvss_score': cve.get('cvss', {}).get('score'),
                                        'cvss_version': cve.get('cvss', {}).get('version'),
                                        'published_date': cve.get('published_date'),
                                        'last_modified': cve.get('last_modified'),
                                        'vector_string': cve.get('cvss', {}).get('vector'),
                                        'references': cve.get('references', [])
                                    }
                                    self.db.add_plugin_cve(plugin_cve_data)

                for file_info in results.get('sensitive_files', []):
                    file_data = {
                        'domain_id': domain_id,
                        'file_path': file_info.get('url', ''),
                        'file_type': file_info.get('file_type', ''),
                        'verification_result': file_info.get('verification_result', ''),
                        'content_sample': file_info.get('content_sample', '')
                    }
                    self.db.add_sensitive_file(file_data)

        except Exception as e:
            logger.error(f"Failed to save results for {domain}: {e}")

    async def scan(self, domains: List[str], max_concurrent: int = None):
        if max_concurrent is None:
            max_concurrent = self.config.get('max_concurrent', 10)

        logger.info(f"Starting scan of {len(domains)} domains with {max_concurrent} concurrent requests")

        semaphore = asyncio.Semaphore(max_concurrent)

        async def scan_with_semaphore(domain):
            async with semaphore:
                return await self.scan_domain(domain)

        tasks = [scan_with_semaphore(domain) for domain in domains]

        results = []
        for i in range(0, len(tasks), max_concurrent):
            batch = tasks[i:i + max_concurrent]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"Task failed with exception: {result}")
                else:
                    results.append(result)

            processed = i + len(batch)
            logger.info(f"Progress: {processed}/{len(domains)} domains processed")

        self._print_stats()

        return results

    def _print_stats(self):
        logger.info("="*50)
        logger.info("SCAN STATISTICS:")
        logger.info(f"Total domains: {self.stats['total']}")
        logger.info(f"Successful: {self.stats['successful']}")
        logger.info(f"Failed: {self.stats['failed']}")
        logger.info(f"With technologies: {self.stats['with_technologies']}")
        logger.info(f"With sensitive files: {self.stats['with_files']}")
        logger.info(f"With cameras: {self.stats['with_cameras']}")
        logger.info("="*50)
