import aiohttp
import asyncio
import json
import time
import re
from typing import Dict, List, Optional, Tuple
from collections import deque
from fullmute.utils.logger import setup_logger

logger = setup_logger()


class RateLimiter:
    def __init__(self, rate: float = 50/30, capacity: int = 10):
        self.rate = rate  
        self.capacity = capacity  
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
        
    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                logger.debug(f"Rate limiter: waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class CVEChecker:
    def __init__(self, nvd_api_key: Optional[str] = None, max_retries: int = 3,
                 initial_delay: float = 1.0, rate_limit: bool = True):
        self.nvd_api_key = nvd_api_key
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {
            "Accept": "application/json"
        }
        if self.nvd_api_key:
            self.headers["apiKey"] = self.nvd_api_key
            
            self.rate_limiter = RateLimiter(rate=50/30, capacity=5) if rate_limit else None
        else:
            
            self.rate_limiter = RateLimiter(rate=5/30, capacity=1) if rate_limit else None

        
        self.max_retries = max_retries
        self.initial_delay = initial_delay

        
        self._cache: Dict[str, dict] = {}
        self._cache_ttl = 3600  
        self._negative_cache_ttl = 60
        
        
        self._session: Optional[aiohttp.ClientSession] = None

        
        self.vendor_mapping = {
            
            'wordpress': 'wordpress',
            'joomla': 'joomla',
            'drupal': 'drupal',
            'magento': 'magento',
            'shopify': 'shopify',
            'prestashop': 'prestashop',
            'opencart': 'opencart',
            'woocommerce': 'woocommerce',
            'vbulletin': 'vbulletin',
            'phpbb': 'phpbb',

            
            'laravel': 'laravel',
            'django': 'djangoproject',
            'ruby on rails': 'ruby-on-rails',
            'express.js': 'expressjs',
            'spring boot': 'spring-framework',
            'symfony': 'symfony',
            'yii': 'yiiframework',
            'codeigniter': 'codeigniter',
            'flask': 'pallets',

            
            'apache': 'apache',
            'apache httpd': 'apache',
            'apache http server': 'apache',
            'nginx': 'nginx',
            'openssh': 'openbsd',
            'vsftpd': 'vsftpd',
            'proftpd': 'proftpd',
            'microsoft-iis': 'microsoft',
            'litespeed': 'litespeed-technologies',
            'openresty': 'openresty',
            'caddy': 'caddy',
            'gunicorn': 'gunicorn',
            'node.js': 'nodejs',
            'tomcat': 'apache',
            'jetty': 'eclipse-foundation',

            
            'cisco': 'cisco',
            'mikrotik': 'mikrotik',
            'ubiquiti': 'ubiquiti-networks',
            'tp-link': 'tp-link',
            'd-link': 'd-link',
            'netgear': 'netgear',
            'linksys': 'linksys',
            'asus': 'asus',
            'huawei': 'huawei',
            'tenda': 'tenda-technology',
            'zyxel': 'zyxel',
            'motorola': 'motorola',
            'buffalo': 'buffalo',
            'belkin': 'belkin',
            'synology': 'synology',

            
            'axis': 'axis-communications',
            'hikvision': 'hikvision',
            'dahua': 'dahuatech',
            'ubiquiti': 'ubiquiti-networks',
            'vivotek': 'vivotek',
            'bosch': 'robert-bosch-gmbh',
            'samsung': 'samsung',
            'sony': 'sony',
            'panasonic': 'panasonic',
            'grandstream': 'grandstream',
            'avigilon': 'avigilon',
            'arecont': 'arecont-vision',
            'basler': 'basler-ag',
            'canon': 'canon',
            'flir': 'flir-systems',

            
            'jquery': 'jquery',
            'react': 'facebook',
            'vue.js': 'vuejs',
            'angular': 'google',
            'bootstrap': 'getbootstrap',
            'lodash': 'lodash',
            'moment.js': 'moment',
            'axios': 'axios',
            'redux': 'redux',
            'webpack': 'webpack',
            'three.js': 'mrdoob',
            'd3.js': 'd3',

            
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'mongodb': 'mongodb',
            'redis': 'redis',
            'sqlite': 'sqlite',
            'oracle': 'oracle',
            'microsoft sql server': 'microsoft',

            
            'php': 'php',
            'python': 'python',
            'java': 'oracle',
            'node.js': 'nodejs',
            'ruby': 'ruby-lang',
            'go': 'golang',
            'c#': 'microsoft',
            'perl': 'perl',

            
            'akismet': 'akismet',
            'wordfence': 'wordfence',
            'yoast seo': 'yoast',
            'jetpack': 'automattic',
            'woocommerce': 'woocommerce',
            'contact form 7': 'contact-form-7',
            'all in one seo pack': 'semper-plugins',
            'wpforms': 'wpforms',
            'gravity forms': 'rocketgenius',
            'duplicate post': 'enrique-chavez',
            'updraftplus': 'updraftplus',
            'backup buddy': 'ithemes',
            'sucuri security': 'sucuri',
            'really simple ssl': 'really-simple-plugins',
            'xml sitemap': 'xml-sitemaps',
            'google analytics': 'google',
            'facebook for woocommerce': 'facebook',
            'mailchimp for woocommerce': 'mailchimp',
            'advanced custom fields': 'elliot-condon',
            'elementor': 'elementor',
            'wp mail smtp': 'wp-mail-smtp',
            'amp': 'ampproject',
            'siteorigin widgets': 'siteorigin',
            'so-widgets-bundle': 'siteorigin',
            'gutenberg': 'wordpress',
            'classic editor': 'wordpress',
            'disable comments': 'wordpress',
            'wp super cache': 'automattic',
            'w3 total cache': 'fredrik-soderqvist',
            'wp rocket': 'wp-rocket',
            'really simple ssl': 'really-simple-plugins',
            'ssl zen': 'ssl-zen',
            'better search replace': 'delicious-brains',
            'broken link checker': 'wpmudev',
            'redirection': 'john-garfunkel',
            'rank math': 'meowapps',
            'seopress': 'seopress',
            'aioseo': 'aioseo',
            'nitropack': 'nitropack',
            'cloudflare': 'cloudflare',
            'nginx helper': 'rtcamp',
            'varnish http purge': 'peter-mct',
            'autoptimize': 'futtta',
            'wp fastest cache': 'wpfastestcache',
            'comet cache': 'comet-cache',
            'swift performance': 'swift-performance',
            'pwa': 'pwa-project',
            'progressive web apps': 'pwa-project',
            'push notifications': 'onesignal',
            'onesignal': 'onesignal',
            'web push': 'onesignal',
            'social media': 'addthis',
            'addtoany': 'addtoany',
            'sharethis': 'sharethis',
            'hello dolly': 'wordpress',
        }

    async def check_cves_for_technology(self, name: str, version: str) -> List[Dict]:
        if not version or version == "":
            return []

        
        vendor = self._map_vendor(name)
        if not vendor:
            logger.info(f"Skipping NVD lookup for {name} {version}: no vendor mapping")
            return []

        
        return await self._query_nvd_api(vendor, name, version)

    def _build_product_variants(self, product: str) -> List[str]:
        raw_name = (product or '').strip()
        if not raw_name:
            return []

        base_variants = []
        normalized = raw_name.lower().replace(' ', '_').replace('-', '_').replace('.', '_')
        for candidate in [raw_name, normalized, raw_name.lower(), raw_name.replace(' ', '_')]:
            if candidate and candidate not in base_variants:
                base_variants.append(candidate)

        alias_map = {
            'apache_http_server': ['apache_http_server', 'http_server', 'httpd', 'apache'],
            'apache': ['apache_http_server', 'http_server', 'httpd', 'apache'],
            'http_server': ['http_server', 'apache_http_server', 'httpd', 'apache'],
            'httpd': ['httpd', 'apache_http_server', 'http_server', 'apache'],
            'nginx': ['nginx', 'nginx_web_server'],
            'nginx_web_server': ['nginx_web_server', 'nginx'],
            'wordpress': ['wordpress'],
            'wp': ['wordpress'],
            'joomla': ['joomla'],
            'drupal': ['drupal'],
            'iis': ['iis', 'microsoft_iis'],
            'microsoft_iis': ['microsoft_iis', 'iis'],
            'tomcat': ['tomcat', 'apache_tomcat'],
            'apache_tomcat': ['apache_tomcat', 'tomcat'],
            'jquery': ['jquery'],
            'bootstrap': ['bootstrap'],
            'node_js': ['node_js', 'nodejs'],
            'nodejs': ['nodejs', 'node_js'],
        }

        candidates = []
        for variant in base_variants:
            key = variant.lower().replace(' ', '_').replace('-', '_').replace('.', '_')
            for alias in alias_map.get(key, [variant]):
                clean = alias.strip()
                if clean and clean not in candidates:
                    candidates.append(clean)

        if not candidates:
            return [raw_name]

        return candidates

    async def _query_nvd_api(self, vendor: str, product: str, version: str) -> List[Dict]:
        vendor = (vendor or '').strip()
        if not vendor:
            return []

        product_variants = self._build_product_variants(product)
        requests = []
        seen_cpe = set()
        for product_variant in product_variants:
            cpe_match = f"cpe:2.3:a:{vendor}:{product_variant}:{version}:*:*:*:*:*:*:*"
            if cpe_match.casefold() in seen_cpe:
                continue
            seen_cpe.add(cpe_match.casefold())
            requests.append((
                product_variant,
                {
                    "cpeName": cpe_match,
                    "isVulnerable": "",
                    "noRejected": "",
                    "resultsPerPage": 2000,
                },
            ))

        version_parts = re.findall(r'\d+', version)
        if version_parts:
            version_prefix = '.'.join(version_parts[:2])
            search_product = (product or '').strip()
            if search_product:
                requests.append((
                    product_variants[0] if product_variants else search_product,
                    {
                        "keywordSearch": f"{search_product} {version_prefix}",
                        "noRejected": "",
                        "resultsPerPage": 2000,
                    },
                ))

        confirmed_cves = {}
        retry_count = 0
        delay = self.initial_delay

        for product_variant, params in requests:
            while retry_count < self.max_retries:
                try:
                    if self._session is None or self._session.closed:
                        self._session = aiohttp.ClientSession(headers=self.headers)

                    async with self._session.get(self.nvd_base_url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            unrelated_count = 0
                            unconfirmed_count = 0

                            for item in data.get('vulnerabilities', []):
                                cve = item.get('cve', {})
                                if not self._matches_product(
                                    cve,
                                    vendor,
                                    product_variant,
                                ):
                                    unrelated_count += 1
                                    continue
                                version_confirmed = self._is_version_affected(
                                    cve,
                                    vendor,
                                    product_variant,
                                    version,
                                )
                                if not version_confirmed:
                                    unconfirmed_count += 1
                                    continue
                                applicability = (
                                    'nvd_affected_data'
                                    if self._matches_affected_product(
                                        cve,
                                        vendor,
                                        product_variant,
                                    )
                                    else 'nvd_exact_cpe_match'
                                )
                                cve_id = cve.get('id')
                                descriptions = cve.get('descriptions', [])
                                description = next((desc['value'] for desc in descriptions if desc.get('lang') == 'en'), '')
                                metrics = cve.get('metrics', {})
                                cvss_data = self._extract_cvss_data(metrics)
                                published = cve.get('published')
                                refs = cve.get('references', [])
                                reference_urls = [ref.get('url') for ref in refs if ref.get('url')]

                                cve_result = {
                                    'id': cve_id,
                                    'description': description,
                                    'cvss': cvss_data,
                                    'published_date': published,
                                    'last_modified': cve.get('lastModified'),
                                    'references': reference_urls,
                                    'applicability': applicability,
                                    'version_range_confirmed': True,
                                }
                                if cve_id:
                                    confirmed_cves[cve_id] = cve_result

                            if unrelated_count:
                                logger.info(
                                    f"Excluded {unrelated_count} unrelated NVD CVE records for "
                                    f"{vendor}:{product_variant}:{version}"
                                )

                            if unconfirmed_count:
                                logger.info(
                                    f"Excluded {unconfirmed_count} NVD CVE records for "
                                    f"{vendor}:{product_variant}:{version}: NVD did not "
                                    "confirm this exact installed version as affected"
                                )

                            break
                        elif response.status == 404:
                            logger.debug(f"No CVEs found for {vendor}:{product_variant}:{version} (status 404)")
                            break
                        elif response.status == 429:
                            retry_after = response.headers.get("Retry-After")
                            try:
                                wait_time = max(delay, float(retry_after)) if retry_after else max(
                                    delay, 6.0 if not self.nvd_api_key else 1.0
                                )
                            except ValueError:
                                wait_time = max(delay, 6.0 if not self.nvd_api_key else 1.0)
                            logger.warning(
                                f"NVD API rate limited (status 429), retrying in {wait_time}s..."
                            )
                            retry_count += 1
                            if retry_count < self.max_retries:
                                await asyncio.sleep(wait_time)
                                delay *= 2
                            else:
                                logger.error("NVD API rate limited, max retries exceeded")
                                return []
                        else:
                            logger.error(f"NVD API request failed with status {response.status}")
                            return []
                except Exception as e:
                    logger.error(f"Error querying NVD API: {e}")
                    retry_count += 1
                    if retry_count < self.max_retries:
                        await asyncio.sleep(delay)
                        delay *= 2
                    else:
                        logger.error(f"NVD API request failed after {self.max_retries} retries: {e}")
                        return []

            retry_count = 0
            delay = self.initial_delay

        return list(confirmed_cves.values())

    @staticmethod
    def _version_key(version: str):
        tokens = re.findall(r'\d+|[a-z]+', version.lower())
        key = [(0, int(token)) if token.isdigit() else (1, token) for token in tokens]
        while key and key[-1] == (0, 0):
            key.pop()
        return tuple(key)

    @classmethod
    def _version_in_range(cls, version: str, match: Dict) -> bool:
        version_key = cls._version_key(version)
        if not version_key:
            return False

        explicit_version = match.get('criteria', '').split(':')[5:6]
        explicit_version = explicit_version[0] if explicit_version else '*'
        if explicit_version == '-':
            return False
        if explicit_version not in {'*', '-'}:
            if version_key != cls._version_key(explicit_version):
                return False

        start_including = match.get('versionStartIncluding')
        start_excluding = match.get('versionStartExcluding')
        end_including = match.get('versionEndIncluding')
        end_excluding = match.get('versionEndExcluding')

        # NVD's unbounded wildcard entries do not establish that this
        # particular installed version is affected.
        if not any((start_including, start_excluding, end_including, end_excluding)):
            return explicit_version not in {'*', '-'}

        if start_including and version_key < cls._version_key(start_including):
            return False
        if start_excluding and version_key <= cls._version_key(start_excluding):
            return False
        if end_including and version_key > cls._version_key(end_including):
            return False
        if end_excluding and version_key >= cls._version_key(end_excluding):
            return False
        return True

    @classmethod
    def _is_version_affected(
        cls,
        cve: Dict,
        vendor: str,
        product: str,
        version: str,
    ) -> bool:
        vendor = vendor.casefold()
        product = product.casefold()

        def walk(node: Dict) -> bool:
            matches = []
            for match in node.get('cpeMatch', []):
                criteria = match.get('criteria', '')
                parts = criteria.split(':')
                if (
                    len(parts) < 6
                    or parts[0:2] != ['cpe', '2.3']
                    or parts[3].casefold() != vendor
                    or parts[4].casefold() != product
                ):
                    matches.append(False)
                    continue
                matches.append(
                    match.get('vulnerable') is True
                    and cls._version_in_range(version, match)
                )

            child_results = [walk(child) for child in node.get('children', [])]
            results = matches + child_results
            if not results or node.get('negate'):
                return False
            if node.get('operator', 'OR').upper() == 'AND':
                return all(results)
            return any(results)

        for configuration in cve.get('configurations', []):
            node_results = [walk(node) for node in configuration.get('nodes', [])]
            if not node_results:
                continue
            if (
                all(node_results)
                if configuration.get('operator', 'OR').upper() == 'AND'
                else any(node_results)
            ):
                return True
        if cls._has_explicit_cpe_version_match(cve, vendor, product):
            return False
        return cls._is_affected_data_version(cve, vendor, product, version)

    @classmethod
    def _has_explicit_cpe_version_match(
        cls,
        cve: Dict,
        vendor: str,
        product: str,
    ) -> bool:
        vendor = vendor.casefold()
        product = product.casefold()

        def walk(node: Dict) -> bool:
            for match in node.get('cpeMatch', []):
                parts = match.get('criteria', '').split(':')
                if (
                    len(parts) >= 6
                    and parts[0:2] == ['cpe', '2.3']
                    and parts[3].casefold() == vendor
                    and parts[4].casefold() == product
                    and match.get('vulnerable') is True
                    and (
                        parts[5] not in {'*', '-'}
                        or any(match.get(field) for field in (
                            'versionStartIncluding',
                            'versionStartExcluding',
                            'versionEndIncluding',
                            'versionEndExcluding',
                        ))
                    )
                ):
                    return True
            return any(walk(child) for child in node.get('children', []))

        return any(
            walk(node)
            for configuration in cve.get('configurations', [])
            for node in configuration.get('nodes', [])
        )

    @staticmethod
    def _matches_affected_product(cve: Dict, vendor: str, product: str) -> bool:
        vendor = CVEChecker._normalize_affected_vendor(vendor)
        product = product.casefold()
        return any(
            isinstance(affected, dict)
            and CVEChecker._normalize_affected_vendor(
                str(affected.get('vendor', ''))
            ) == vendor
            and str(affected.get('product', '')).casefold() == product
            for affected in CVEChecker._iter_affected_products(cve)
        )

    @staticmethod
    def _normalize_affected_vendor(vendor: str) -> str:
        normalized = re.sub(r'\s+', ' ', vendor.casefold().strip())
        aliases = {
            'wordpress.org': 'wordpress',
            'wordpress foundation': 'wordpress',
            'automattic': 'wordpress',
        }
        return aliases.get(normalized, normalized)

    @staticmethod
    def _iter_affected_products(cve: Dict):
        for affected_record in cve.get('affected', []):
            if not isinstance(affected_record, dict):
                continue
            affected_data = affected_record.get('affectedData')
            if isinstance(affected_data, list):
                yield from (
                    item for item in affected_data if isinstance(item, dict)
                )
            else:
                yield affected_record

    @classmethod
    def _is_affected_data_version(
        cls,
        cve: Dict,
        vendor: str,
        product: str,
        version: str,
    ) -> bool:
        target_key = cls._version_key(version)
        if not target_key:
            return False

        for affected in cls._iter_affected_products(cve):
            if (
                not isinstance(affected, dict)
                or cls._normalize_affected_vendor(
                    str(affected.get('vendor', ''))
                ) != cls._normalize_affected_vendor(vendor)
                or str(affected.get('product', '')).casefold() != product.casefold()
            ):
                continue

            for version_entry in affected.get('versions', []):
                if not isinstance(version_entry, dict) or version_entry.get('status') != 'affected':
                    continue

                start_version = str(version_entry.get('version', '*'))
                if start_version not in {'*', '-'}:
                    start_key = cls._version_key(start_version)
                    if not start_key or target_key < start_key:
                        continue

                less_than = version_entry.get('lessThan')
                less_than_or_equal = version_entry.get('lessThanOrEqual')
                if less_than and target_key >= cls._version_key(str(less_than)):
                    continue
                if less_than_or_equal and target_key > cls._version_key(str(less_than_or_equal)):
                    continue

                if not less_than and not less_than_or_equal and start_version not in {'*', '-'}:
                    if target_key != cls._version_key(start_version):
                        continue

                status = 'affected'
                for change in sorted(
                    version_entry.get('changes', []),
                    key=lambda item: cls._version_key(str(item.get('at', '')))
                    if isinstance(item, dict) else (),
                ):
                    if not isinstance(change, dict) or not change.get('at'):
                        continue
                    if target_key < cls._version_key(str(change['at'])):
                        break
                    status = change.get('status', status)

                if status == 'affected':
                    return True

        return False

    @staticmethod
    def _matches_product(cve: Dict, vendor: str, product: str) -> bool:
        vendor = vendor.casefold()
        product = product.casefold()

        def walk(node: Dict) -> bool:
            for match in node.get('cpeMatch', []):
                parts = match.get('criteria', '').split(':')
                if (
                    len(parts) >= 6
                    and parts[0:2] == ['cpe', '2.3']
                    and parts[3].casefold() == vendor
                    and parts[4].casefold() == product
                    and match.get('vulnerable') is True
                ):
                    return True
            return any(walk(child) for child in node.get('children', []))

        has_cpe_match = any(
            walk(node)
            for configuration in cve.get('configurations', [])
            for node in configuration.get('nodes', [])
        )
        return has_cpe_match or CVEChecker._matches_affected_product(
            cve, vendor, product
        )

    def _extract_cvss_data(self, metrics: Dict) -> Dict:
        cvss_data = {}
        
        
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            metric = metrics['cvssMetricV31'][0]
            cvss_data = {
                'version': '3.1',
                'score': metric.get('cvssData', {}).get('baseScore'),
                'severity': metric.get('cvssData', {}).get('baseSeverity'),
                'vector': metric.get('cvssData', {}).get('vectorString')
            }
        
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            metric = metrics['cvssMetricV30'][0]
            cvss_data = {
                'version': '3.0',
                'score': metric.get('cvssData', {}).get('baseScore'),
                'severity': metric.get('cvssData', {}).get('baseSeverity'),
                'vector': metric.get('cvssData', {}).get('vectorString')
            }
        
        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            metric = metrics['cvssMetricV2'][0]
            cvss_data = {
                'version': '2.0',
                'score': metric.get('cvssData', {}).get('baseScore'),
                'severity': metric.get('severity'),
                'vector': metric.get('cvssData', {}).get('vectorString')
            }
        
        return cvss_data

    def _map_vendor(self, technology_name: str) -> Optional[str]:
        name_lower = technology_name.lower().replace(' ', '_').replace('.', '').replace('-', '_')
        
        normalized_mapping = {
            key.lower().replace(' ', '_').replace('.', '').replace('-', '_'): value
            for key, value in self.vendor_mapping.items()
        }
        if name_lower in normalized_mapping:
            return normalized_mapping[name_lower]
        return None

    async def check_cves_batch(self, technologies: List[Tuple[str, str]]) -> Dict[str, List[Dict]]:
        results = {}
        
        
        techs_to_check = []
        for name, version in technologies:
            cache_key = f"{name}_{version}"
            
            
            if cache_key in self._cache:
                cached_result = self._cache[cache_key]
                cache_ttl = cached_result.get(
                    'ttl',
                    self._cache_ttl if cached_result.get('cves') else self._negative_cache_ttl
                )
                if time.time() - cached_result.get('timestamp', 0) < cache_ttl:
                    if cached_result.get('cves'):
                        results[f"{name} ({version})"] = cached_result['cves']
                    continue
            
            techs_to_check.append((name, version))
        
        if not techs_to_check:
            logger.debug(f"All CVE results cached, skipping API calls")
            return results
        
        logger.info(f"Checking CVEs for {len(techs_to_check)} technologies (cached {len(technologies) - len(techs_to_check)})")

        
        batch_size = 3  

        for i in range(0, len(techs_to_check), batch_size):
            batch = techs_to_check[i:i + batch_size]

            
            for name, version in batch:
                
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                cves = await self.check_cves_for_technology(name, version)
                
                
                cache_key = f"{name}_{version}"
                self._cache[cache_key] = {
                    'cves': cves,
                    'timestamp': time.time(),
                    'ttl': self._cache_ttl if cves else self._negative_cache_ttl,
                }
                
                if cves:
                    results[f"{name} ({version})"] = cves

                
                await asyncio.sleep(0.3)

            
            if i + batch_size < len(techs_to_check):
                await asyncio.sleep(1.0)

        logger.info(f"CVE check completed: {len(results)} technologies with CVEs found")
        return results
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("CVE checker HTTP session closed")
