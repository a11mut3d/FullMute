import asyncio
import gc
import multiprocessing
import re
import time
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from urllib.parse import urlsplit, urlunsplit
from fullmute.detector.signature_loader import SignatureLoader
from fullmute.detector.tech_detector import TechDetector
from fullmute.core.verifier import SensitiveFileVerifier
from fullmute.db.queries import DBQueries
from fullmute.utils.http_client import HttpClient
from fullmute.utils.logger import setup_logger
from fullmute.utils.stealth import Stealth
from fullmute.utils.cve_checker import CVEChecker
from fullmute.detector.default_creds_checker import DefaultCredentialsChecker

logger = setup_logger()


def _detect_technologies_worker(connection, url, headers, html, cookies, signatures):
    """Run regex-heavy detection in a killable process."""
    try:
        result = TechDetector(
            url=url,
            headers=headers,
            html=html,
            cookies=cookies,
            signatures=signatures
        ).detect()
        connection.send(("ok", result))
    except Exception as e:
        connection.send(("error", str(e)))
    finally:
        connection.close()


class FullMuteScanner:
    def __init__(self, db_path: str, config: Dict[str, Any] = None):
        self.db_path = db_path
        self.config = config or {}

        self._closed = False
        self._scan_count = 0
        # Увеличил порог очистки, чтобы она реже срабатывала (опционально)
        self._max_scans_before_cleanup = self.config.get('max_scans_before_cleanup', 200)

        self.db = DBQueries(db_path)
        self.signature_loader = SignatureLoader()
        self.signatures = self.signature_loader.load_all()

        max_concurrent = self.config.get('max_concurrent', 10)
        self.http_client = HttpClient(
            max_retries=self.config.get('max_retries', 3),
            timeout=self.config.get('timeout', 15),
            proxy_enabled=self.config.get('proxy_enabled', False),
            proxy_file=self.config.get('proxy_file'),
            bypass_cloudflare=self.config.get('bypass_cloudflare', True),
            max_redirects=self.config.get('max_redirects', 5),
            max_concurrent=max_concurrent,
            enable_session_cache=True
        )

        self.verifier = SensitiveFileVerifier(
            self.signatures.get('sensitive_files', {})
        )

        self.stealth = Stealth(
            min_delay=self.config.get('min_delay', 1.0),
            max_delay=self.config.get('max_delay', 3.0),
            rotate_user_agents=self.config.get('rotate_user_agents', True)
        )

        self.cve_checker = CVEChecker(
            nvd_api_key=self.config.get('nvd_api_key'),
            max_retries=self.config.get('nvd_max_retries', 3),
            initial_delay=self.config.get('nvd_initial_delay', 1.0)
        )

        self.creds_checker = DefaultCredentialsChecker(
            timeout=self.config.get('timeout', 10),
            max_attempts=self.config.get('creds_max_attempts', 5),
            path_probe_concurrency=self.config.get(
                'login_path_probe_concurrency', 8
            ),
        )

        self.stats = {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'with_technologies': 0,
            'with_files': 0,
            'with_cameras': 0,
            'with_cves': 0,
            'with_default_creds': 0
        }

        logger.info(f"FullMuteScanner initialized: db={db_path}, max_concurrent={max_concurrent}")

    async def scan_domain(self, domain: str):
        scan_started = time.perf_counter()
        stage_timings = {}
        self.stats['total'] += 1

        results = {
            "domain": domain,
            "technologies": {},
            "cameras": [],
            "sensitive_files": [],
            "cves": {},
            "default_credentials": [],
            "error": None,
            "status_code": 0
        }

        try:
            logger.info(f"scan_domain start: {domain}")
            url = f"http://{domain}" if not domain.startswith("http") else domain

            stage_started = time.perf_counter()
            logger.info(f"Fetching URL: {url}")
            html, headers_dict, cookies_dict, status_code, final_url = await self.http_client.fetch(url)
            stage_timings['fetch'] = time.perf_counter() - stage_started
            logger.info(f"Fetch completed: status={status_code}, final_url={final_url}")
            results["status_code"] = status_code
            results["final_url"] = final_url

            if html is None:
                results["error"] = "Failed to fetch site data"
                self.stats['failed'] += 1
                return results

            self.stats['successful'] += 1

            logger.info(f"Running TechDetector for {final_url}")
            stage_started = time.perf_counter()
            detection_limit = max(
                100_000,
                int(self.config.get('tech_detection_max_html', 2_000_000))
            )
            detection_html = html[:detection_limit]
            tech_detector = TechDetector(
                url=final_url,
                headers=headers_dict,
                html=detection_html,
                cookies=cookies_dict,
                signatures=self.signatures
            )

            technologies = await self._detect_technologies_with_timeout(
                tech_detector,
                timeout=max(1.0, float(self.config.get('tech_detection_timeout', 15)))
            )

            if any(
                tech.split(' (', 1)[0].strip().casefold() in {'joomla', 'joomla!'}
                for tech_list in technologies.values()
                for tech in tech_list
            ):
                joomla_version = await self._fetch_joomla_xml_version(final_url)
                if joomla_version:
                    for tech_list in technologies.values():
                        for index, tech in enumerate(tech_list):
                            name = tech.split(' (', 1)[0].strip()
                            if name.casefold() in {'joomla', 'joomla!'}:
                                tech_list[index] = f"{name} ({joomla_version})"
                    logger.info(
                        f"Joomla version confirmed from language XML: "
                        f"{joomla_version}"
                    )
            stage_timings['technology_detection'] = time.perf_counter() - stage_started

            results["technologies"] = technologies
            logger.debug(f"Tech detection result for {domain}: {list(technologies.keys())}")

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
            for tech_list in technologies.values():
                for tech in tech_list:
                    if not isinstance(tech, str) or ' (' not in tech or not tech.endswith(')'):
                        if isinstance(tech, str):
                            logger.info(
                                f"Skipping NVD CVE lookup for detected technology "
                                f"without an explicit version: {tech}"
                            )
                        continue
                    name, version = tech.rsplit(' (', 1)
                    version = version[:-1].strip()
                    if name.strip() and version:
                        tech_with_versions.append((name.strip(), version))
                    else:
                        logger.info(
                            f"Skipping NVD CVE lookup for detected technology "
                            f"with an empty name or version: {tech}"
                        )

            tech_with_versions = list(dict.fromkeys(tech_with_versions))

            if not tech_with_versions and any(technologies.values()):
                logger.info(
                    f"Technologies detected for {domain}, but no explicit versions were found; "
                    "skipping version-specific NVD CVE lookup"
                )

            stage_started = time.perf_counter()
            if tech_with_versions:
                logger.info(
                    f"Checking CVEs for {len(tech_with_versions)} techs: "
                    f"{tech_with_versions}"
                )
                try:
                    cve_results = await self.cve_checker.check_cves_batch(tech_with_versions)
                    results["cves"] = cve_results

                    if cve_results:
                        self.stats['with_cves'] += 1
                        total_cves = sum(len(items) for items in cve_results.values())
                        logger.info(
                            f"Found {total_cves} CVEs across "
                            f"{len(cve_results)} technologies for {domain}"
                        )
                        cve_ids = list(dict.fromkeys(
                            cve.get('id')
                            for items in cve_results.values()
                            for cve in items
                            if cve.get('id')
                        ))

                        if self.config.get('search_exploits') and cve_ids:
                            from fullmute.utils.searchsploit import search_sploit_batch
                            results["exploits"] = await asyncio.get_running_loop().run_in_executor(
                                None, search_sploit_batch, cve_ids
                            )
                            for items in cve_results.values():
                                for cve in items:
                                    cve["exploits"] = results["exploits"].get(cve.get("id"), [])

                        if self.config.get('nuclei_enabled') and cve_ids:
                            from fullmute.utils.nuclei import NucleiRunner
                            results["nuclei"] = await NucleiRunner(
                                binary=self.config.get('nuclei_binary', 'nuclei'),
                                templates_path=(
                                    self.config.get('nuclei_templates_path')
                                    or './nuclei-templates'
                                ),
                                timeout=self.config.get('nuclei_timeout', 120),
                            ).run_for_cves(final_url, cve_ids)
                except Exception as e:
                    logger.exception(
                        f"CVE lookup or enrichment failed for {domain}: {e}"
                    )
            stage_timings['cve_lookup'] = time.perf_counter() - stage_started

            stage_started = time.perf_counter()
            logger.info(f"Running SensitiveFileVerifier for {final_url}")
            try:
                sensitive_files = await self.verifier.verify(None, results.get('final_url', url))
            except Exception as e:
                logger.info(f"Sensitive file verifier error for {domain}: {e}")
                sensitive_files = []
            stage_timings['sensitive_file_checks'] = time.perf_counter() - stage_started

            results["sensitive_files"] = sensitive_files

            if sensitive_files:
                self.stats['with_files'] += 1

            stage_started = time.perf_counter()
            if self.config.get('test_default_credentials', True):
                try:
                    detected_tech = []
                    for tech_type, tech_list in technologies.items():
                        for tech in tech_list:
                            if ' (' in tech:
                                detected_tech.append(tech.split(' (')[0])
                            else:
                                detected_tech.append(tech)

                    logger.info(f"Testing default credentials for {domain} (techs: {detected_tech})")
                    creds_result = await asyncio.wait_for(
                        self.creds_checker.check_url(
                            results.get('final_url', url),
                            html,
                            detected_tech
                        ),
                        timeout=max(30.0, self.config.get('timeout', 15) * 2)
                    )

                    if creds_result.get('successful_logins'):
                        results["default_credentials"] = creds_result['successful_logins']
                        self.stats['with_default_creds'] += 1
                        logger.warning(
                            f"FOUND DEFAULT CREDENTIALS on {domain}: "
                            f"{len(creds_result['successful_logins'])} successful login(s)!"
                        )
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout checking default credentials for {domain}")
                    results["default_credentials"] = []
                except Exception as e:
                    logger.debug(f"Error checking default credentials for {domain}: {e}")
                    results["default_credentials"] = []
            else:
                results["default_credentials"] = []
                logger.debug(f"Default credentials test disabled for {domain}")
            stage_timings['default_credential_checks'] = time.perf_counter() - stage_started

            logger.info(f"Saving results for {domain}")
            stage_started = time.perf_counter()
            self._save_to_db(domain, results)
            stage_timings['database_persistence'] = time.perf_counter() - stage_started

            logger.info(
                f"Scanned {domain} - Tech: {len(technologies.get('cms', []))} CMS, "
                f"CVEs: {sum(len(items) for items in results['cves'].values())}, "
                f"Files: {len(sensitive_files)}, "
                f"Default Cred: {len(results['default_credentials'])}"
            )

        except Exception as e:
            logger.error(f"Error scanning {domain}: {e}")
            results["error"] = str(e)
            self.stats['failed'] += 1
        finally:
            logger.info(
                "Scan timing for %s: total=%.2fs stages=%s",
                domain,
                time.perf_counter() - scan_started,
                {
                    stage: round(duration, 2)
                    for stage, duration in stage_timings.items()
                },
            )

        return results

    async def _fetch_joomla_xml_version(self, site_url: str) -> str:
        parsed_url = urlsplit(site_url)
        if not parsed_url.hostname:
            logger.warning(
                "Cannot check Joomla version XML: invalid site URL %s",
                site_url,
            )
            return ""

        hostname = parsed_url.hostname
        if ':' in hostname and not hostname.startswith('['):
            hostname = f"[{hostname}]"

        port = parsed_url.port
        if port and not (
            parsed_url.scheme == 'http' and port == 80
        ):
            hostname = f"{hostname}:{port}"

        xml_url = urlunsplit((
            'https',
            hostname,
            '/language/en-GB/en-GB.xml',
            '',
            '',
        ))

        try:
            body, _, _, status_code, _ = await self.http_client.fetch(xml_url)
        except Exception:
            logger.exception("Joomla version XML request failed: %s", xml_url)
            return ""

        if not body or status_code != 200:
            logger.info(
                "Joomla version XML unavailable at %s (HTTP %s)",
                xml_url,
                status_code,
            )
            return ""

        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            logger.warning("Invalid Joomla version XML returned by %s", xml_url)
            return ""

        for element in root.iter():
            if element.tag.rsplit('}', 1)[-1].casefold() != 'version':
                continue
            version = (element.text or '').strip()
            if re.fullmatch(r'\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?', version):
                return version

        logger.info("No valid <version> tag found in Joomla XML at %s", xml_url)
        return ""

    async def _detect_technologies_with_timeout(self, detector: TechDetector,
                                                timeout: float) -> Dict[str, List[str]]:
        """Run detection outside the event loop and terminate pathological regex work."""
        context = multiprocessing.get_context("spawn")
        parent_connection, child_connection = context.Pipe(duplex=False)
        process = context.Process(
            target=_detect_technologies_worker,
            args=(
                child_connection,
                detector.url,
                detector.headers,
                detector.html,
                detector.cookies,
                detector.signatures,
            ),
            daemon=True,
        )
        process.start()
        child_connection.close()

        try:
            deadline = asyncio.get_running_loop().time() + timeout
            while not parent_connection.poll():
                if asyncio.get_running_loop().time() >= deadline:
                    logger.warning("TechDetector timed out; terminating worker process")
                    process.terminate()
                    await asyncio.to_thread(process.join, 2)
                    if process.is_alive():
                        process.kill()
                        await asyncio.to_thread(process.join, 1)
                    return {}
                await asyncio.sleep(0.05)

            status, payload = parent_connection.recv()
            if status == "error":
                logger.warning(f"TechDetector failed: {payload}")
                return {}
            return payload if isinstance(payload, dict) else {}
        finally:
            parent_connection.close()
            if process.is_alive():
                process.terminate()
            await asyncio.to_thread(process.join, 1)

    def _save_to_db(self, domain: str, results: Dict[str, Any]):
        try:
            domain_data = {
                'domain': domain,
                'has_camera': len(results.get('cameras', [])) > 0,
                'is_alive': results.get('error') is None,
                'http_status': results.get('status_code', 0),
                'final_url': results.get('final_url', '')
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
                nuclei_by_cve = {}
                for item in results.get('nuclei', []):
                    if not isinstance(item, dict) or not item.get('cve_id'):
                        continue
                    nuclei_by_cve.setdefault(item['cve_id'], []).append({
                        'cve_id': item.get('cve_id'),
                        'template_name': item.get('template_name') or (
                            str(item.get('template', '')).replace(
                                '\\', '/'
                            ).rsplit('/', 1)[-1]
                            if item.get('template') else None
                        ),
                        'template': item.get('template'),
                        'status': item.get('status', 'unknown'),
                        'findings_count': len(item.get('findings', []))
                        if isinstance(item.get('findings'), list) else 0,
                    })
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
                                        'references': cve.get('references', []),
                                        'applicability': cve.get('applicability'),
                                        'exploits': cve.get('exploits', []),
                                        'nuclei_templates': nuclei_by_cve.get(
                                            cve.get('id'), []
                                        ),
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
                                        'references': cve.get('references', []),
                                        'exploits': cve.get('exploits', []),
                                        'nuclei_templates': nuclei_by_cve.get(
                                            cve.get('id'), []
                                        ),
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

                for cred in results.get('default_credentials', []):
                    cred_data = {
                        'domain_id': domain_id,
                        'login_url': cred.get('url', ''),
                        'username': cred.get('username', ''),
                        'password': cred.get('password', ''),
                        'description': cred.get('description', ''),
                        'detection_reason': cred.get('reason', '')
                    }
                    self.db.add_default_credential(cred_data)

        except Exception as e:
            logger.error(f"Failed to save results for {domain}: {e}")

    async def scan(self, domains: List[str], max_concurrent: int = None):
        if max_concurrent is None:
            max_concurrent = self.config.get('max_concurrent', 10)

        logger.info(f"Starting scan of {len(domains)} domains with {max_concurrent} concurrent requests")

        semaphore = asyncio.Semaphore(max_concurrent)

        consecutive_failures = 0
        max_consecutive_failures = max_concurrent * 2

        async def scan_with_semaphore(domain):
            nonlocal consecutive_failures
            async with semaphore:
                try:
                    result = await asyncio.wait_for(
                        self.scan_domain(domain),
                        timeout=self.config.get('timeout', 15) * 2
                    )

                    if result.get('error') is None:
                        consecutive_failures = 0
                    else:
                        consecutive_failures += 1

                    return result
                except asyncio.TimeoutError:
                    consecutive_failures += 1
                    logger.warning(f"Timeout scanning domain {domain} (failures: {consecutive_failures})")

                    if consecutive_failures >= max_consecutive_failures:
                        logger.error(f"Too many consecutive failures ({consecutive_failures}), "
                                   f"consider reducing concurrent scans or checking network")

                    return {
                        "domain": domain,
                        "technologies": {},
                        "cameras": [],
                        "sensitive_files": [],
                        "cves": {},
                        "error": "Timeout during scan",
                        "status_code": 0
                    }

        tasks = [scan_with_semaphore(domain) for domain in domains]

        results = []
        for i in range(0, len(tasks), max_concurrent):
            batch = tasks[i:i + max_concurrent]
            try:
                batch_results = await asyncio.wait_for(
                    asyncio.gather(*batch, return_exceptions=True),
                    timeout=self.config.get('timeout', 15) * 3
                )
            except asyncio.TimeoutError:
                logger.warning(f"Timeout processing batch of domains")
                batch_results = []
                for _ in range(len(batch)):
                    domain_idx = i + len(results)
                    if domain_idx < len(domains):
                        results.append({
                            "domain": domains[domain_idx],
                            "technologies": {},
                            "cameras": [],
                            "sensitive_files": [],
                            "cves": {},
                            "error": "Timeout during scan",
                            "status_code": 0
                        })

            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"Task failed with exception: {result}")
                    consecutive_failures += 1
                else:
                    results.append(result)

            processed = i + len(batch)
            logger.info(f"Progress: {processed}/{len(domains)} domains processed "
                       f"(consecutive failures: {consecutive_failures})")

            if processed % 20 == 0:
                await self._periodic_cleanup()

        await self.http_client.close()

        self._print_stats()

        return results

    # ======================= ИСПРАВЛЕННЫЙ МЕТОД =======================
    async def _periodic_cleanup(self):
        self._scan_count += 1

        if self._scan_count >= self._max_scans_before_cleanup:
            logger.debug("Running periodic garbage collection")
            self._scan_count = 0

            # Сборка мусора – безопасна и не влияет на активные запросы
            gc.collect()

            # УДАЛЁН ВЫЗОВ await self.http_client.close()
            # Раньше он закрывал сеанс, что приводило к сбою всех текущих запросов
            # с ошибкой "Last error: None". Теперь этого не происходит.
            #
            # При необходимости пересоздавать сеанс не нужно – HttpClient управляет
            # своим соединением самостоятельно.
    # =================================================================

    async def close(self):
        if self._closed:
            return

        self._closed = True
        logger.info("Closing scanner and releasing resources")

        try:
            await self.http_client.close()
        except Exception as e:
            logger.debug(f"Error closing HTTP client: {e}")

        try:
            await self.cve_checker.close()
        except Exception as e:
            logger.debug(f"Error closing CVE checker: {e}")

        try:
            # Ensure default credentials checker sessions are closed
            if hasattr(self, 'creds_checker') and self.creds_checker:
                await self.creds_checker.close()
        except Exception as e:
            logger.debug(f"Error closing creds checker: {e}")

        gc.collect()
        logger.debug("Scanner closed")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

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
