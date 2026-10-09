import aiohttp
import asyncio
import re
import time
from typing import Dict, List, Optional, Tuple
from fullmute.utils.logger import setup_logger

logger = setup_logger()


class CVECheckResults(dict):
    def __init__(self):
        super().__init__()
        self.completed_lookups = set()


class NVDLookupError(RuntimeError):
    """Raised when the NVD API did not complete a CVE lookup successfully."""


class RateLimiter:
    def __init__(self, rate: float = 50/30, capacity: int = 10):
        self.rate = rate  
        self.capacity = capacity  
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
        
    async def acquire(self):
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.tokens = min(
                    self.capacity,
                    self.tokens + elapsed * self.rate,
                )
                self.last_update = now

                if self.tokens >= 1:
                    self.tokens -= 1
                    return

                wait_time = (1 - self.tokens) / self.rate
                logger.debug(f"Rate limiter: waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)


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
        self._cache_lock = asyncio.Lock()
        self._inflight: Dict[str, asyncio.Task] = {}
        
        
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
            logger.warning(
                f"Skipping NVD lookup for detected technology {name} {version}: "
                "no NVD vendor mapping exists"
            )
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

    @staticmethod
    def _version_parts(version: str) -> Optional[Tuple[int, ...]]:
        parts = re.findall(r'\d+', version or '')
        return tuple(int(part) for part in parts) if parts else None

    @classmethod
    def _version_matches_cpe(
        cls,
        detected_version: str,
        cpe_version: str,
        cpe_match: Dict,
    ) -> bool:
        detected_parts = cls._version_parts(detected_version)
        if detected_parts is None:
            return False

        if cpe_version == '-':
            return False
        version_bound_fields = (
            'versionStartIncluding',
            'versionStartExcluding',
            'versionEndIncluding',
            'versionEndExcluding',
        )
        has_version_bounds = any(cpe_match.get(field) for field in version_bound_fields)
        if cpe_version in {'', '*'} and not has_version_bounds:
            return False
        if cpe_version not in {'', '*'}:
            if '*' in cpe_version:
                prefix_parts = cls._version_parts(cpe_version.split('*', 1)[0].rstrip('.'))
                if prefix_parts and detected_parts[:len(prefix_parts)] != prefix_parts:
                    return False
            else:
                cpe_parts = cls._version_parts(cpe_version)
                if cpe_parts is None or detected_parts != cpe_parts:
                    return False

        for field, inclusive, lower_bound in (
            ('versionStartIncluding', True, True),
            ('versionStartExcluding', False, True),
            ('versionEndIncluding', True, False),
            ('versionEndExcluding', False, False),
        ):
            bound = cpe_match.get(field)
            if not bound:
                continue
            bound_parts = cls._version_parts(str(bound))
            if bound_parts is None:
                return False
            width = max(len(detected_parts), len(bound_parts))
            detected = detected_parts + (0,) * (width - len(detected_parts))
            boundary = bound_parts + (0,) * (width - len(bound_parts))
            if lower_bound and (
                detected < boundary if inclusive else detected <= boundary
            ):
                return False
            if not lower_bound and (
                detected > boundary if inclusive else detected >= boundary
            ):
                return False

        return True

    @classmethod
    def _matches_vulnerable_cpe(
        cls,
        cve: Dict,
        vendor: str,
        products: List[str],
        version: str,
    ) -> bool:
        normalized_vendor = vendor.casefold()
        normalized_products = {
            product.casefold().replace('-', '_').replace(' ', '_')
            for product in products
        }

        def find_matching_cpe(value):
            if isinstance(value, dict):
                criteria = value.get('criteria') or value.get('cpe23Uri')
                if criteria and value.get('vulnerable') is True:
                    fields = criteria.split(':')
                    if len(fields) >= 6 and fields[0:2] == ['cpe', '2.3']:
                        cpe_vendor = fields[3].casefold()
                        cpe_product = fields[4].casefold().replace('-', '_')
                        if (
                            cpe_vendor == normalized_vendor
                            and cpe_product in normalized_products
                            and cls._version_matches_cpe(
                                version,
                                fields[5],
                                value,
                            )
                        ):
                            return True
                return any(find_matching_cpe(child) for child in value.values())
            if isinstance(value, list):
                return any(find_matching_cpe(child) for child in value)
            return False

        return find_matching_cpe(cve.get('configurations', []))

    async def _query_nvd_api(self, vendor: str, product: str, version: str) -> List[Dict]:
        vendor = (vendor or '').strip()
        if not vendor:
            return []

        product_variants = self._build_product_variants(product)
        requests = []
        seen_cpe = set()
        for product_variant in product_variants:
            cpe_match = (
                f"cpe:2.3:a:{vendor.lower()}:{product_variant.lower()}:"
                f"{version}:*:*:*:*:*:*:*"
            )
            if cpe_match.casefold() in seen_cpe:
                continue
            seen_cpe.add(cpe_match.casefold())
            requests.append((
                product_variant,
                {
                    "cpeName": cpe_match,
                    "resultsPerPage": 2000,
                },
            ))

        found_cves = {}
        successful_requests = 0
        retry_count = 0
        delay = self.initial_delay

        def add_cve(item, applicability, version_range_confirmed=True):
            cve = item.get('cve', {})
            cve_id = cve.get('id')
            if not cve_id:
                return
            descriptions = cve.get('descriptions', [])
            description = next(
                (desc['value'] for desc in descriptions if desc.get('lang') == 'en'),
                '',
            )
            metrics = cve.get('metrics', {})
            refs = cve.get('references', [])
            found_cves[cve_id] = {
                'id': cve_id,
                'description': description,
                'cvss': self._extract_cvss_data(metrics),
                'published_date': cve.get('published'),
                'last_modified': cve.get('lastModified'),
                'references': [ref.get('url') for ref in refs if ref.get('url')],
                'applicability': applicability,
                'version_range_confirmed': version_range_confirmed,
            }

        for product_variant, params in requests:
            page_start = 0
            while retry_count < self.max_retries:
                try:
                    if self._session is None or self._session.closed:
                        self._session = aiohttp.ClientSession(headers=self.headers)

                    if page_start:
                        params["startIndex"] = page_start
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    async with self._session.get(self.nvd_base_url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            successful_requests += 1
                            logger.debug(
                                "NVD returned %s CVE records for %s",
                                data.get('totalResults', 0),
                                params.get('cpeName'),
                            )
                            matched_count = 0
                            for item in data.get('vulnerabilities', []):
                                cve = item.get('cve', {})
                                if self._matches_vulnerable_cpe(
                                    cve,
                                    vendor,
                                    product_variants,
                                    version,
                                ):
                                    add_cve(item, 'nvd_exact_cpe_match')
                                    matched_count += 1
                            if data.get('vulnerabilities') and not matched_count:
                                logger.info(
                                    "NVD exact CPE returned %s records for %s %s, "
                                    "but none mark that product/version as vulnerable",
                                    len(data['vulnerabilities']),
                                    product,
                                    version,
                                )

                            vulnerabilities = data.get('vulnerabilities', [])
                            total_results = int(data.get('totalResults', len(vulnerabilities)))
                            next_start = page_start + len(vulnerabilities)
                            if vulnerabilities and next_start < total_results:
                                page_start = next_start
                                continue
                            break
                        elif response.status == 404:
                            logger.debug(
                                "NVD has no exact CPE entry for %s; "
                                "will try version-aware keyword lookup if needed",
                                params.get('cpeName'),
                            )
                            break
                        elif response.status in {403, 429}:
                            retry_after = response.headers.get("Retry-After")
                            try:
                                wait_time = max(delay, float(retry_after)) if retry_after else max(
                                    delay, 6.0 if not self.nvd_api_key else 1.0
                                )
                            except ValueError:
                                wait_time = max(delay, 6.0 if not self.nvd_api_key else 1.0)
                            logger.warning(
                                "NVD API rate limited or forbidden "
                                f"(status {response.status}), retrying in {wait_time}s..."
                            )
                            retry_count += 1
                            if retry_count < self.max_retries:
                                await asyncio.sleep(wait_time)
                                delay *= 2
                            else:
                                raise NVDLookupError(
                                    f"NVD rate limit retries exhausted "
                                    f"(HTTP {response.status}) for "
                                    f"{params.get('cpeName')}"
                                )
                        else:
                            raise NVDLookupError(
                                f"NVD API request failed with HTTP "
                                f"{response.status} for {params.get('cpeName')}"
                            )
                except NVDLookupError:
                    raise
                except Exception as e:
                    logger.error(f"Error querying NVD API: {e}")
                    retry_count += 1
                    if retry_count < self.max_retries:
                        await asyncio.sleep(delay)
                        delay *= 2
                    else:
                        raise NVDLookupError(
                            f"NVD request failed after {self.max_retries} "
                            f"attempts for {params.get('cpeName')}: {e}"
                        ) from e

            retry_count = 0
            delay = self.initial_delay

        if not found_cves:
            keyword_params = {
                'keywordSearch': f"{product} {version}",
                'resultsPerPage': 2000,
            }
            page_start = 0
            while retry_count < self.max_retries:
                try:
                    if self._session is None or self._session.closed:
                        self._session = aiohttp.ClientSession(headers=self.headers)
                    if page_start:
                        keyword_params['startIndex'] = page_start
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    async with self._session.get(
                        self.nvd_base_url,
                        params=keyword_params,
                    ) as response:
                        if response.status in {403, 429}:
                            retry_count += 1
                            retry_after = response.headers.get('Retry-After')
                            try:
                                wait_time = max(
                                    delay,
                                    float(retry_after) if retry_after else (
                                        6.0 if not self.nvd_api_key else 1.0
                                    ),
                                )
                            except ValueError:
                                wait_time = max(
                                    delay,
                                    6.0 if not self.nvd_api_key else 1.0,
                                )
                            if retry_count >= self.max_retries:
                                raise NVDLookupError(
                                    f"NVD keyword search retries exhausted "
                                    f"(HTTP {response.status}) for "
                                    f"{product} {version}"
                                )
                            logger.warning(
                                "NVD keyword fallback was rate limited "
                                "(HTTP %s); retrying in %ss",
                                response.status,
                                wait_time,
                            )
                            await asyncio.sleep(wait_time)
                            delay *= 2
                            continue
                        if response.status != 200:
                            raise NVDLookupError(
                                f"NVD keyword search failed with HTTP "
                                f"{response.status} for {product} {version}"
                            )
                        data = await response.json()
                        successful_requests += 1
                        matched_count = 0
                        for item in data.get('vulnerabilities', []):
                            cve = item.get('cve', {})
                            configurations = cve.get('configurations')
                            if configurations and self._matches_vulnerable_cpe(
                                cve, vendor, product_variants, version
                            ):
                                add_cve(item, 'nvd_keyword_cpe_match')
                                matched_count += 1
                        logger.info(
                            "NVD keyword fallback for %s %s returned %s records; "
                            "%s matched the product/version configuration",
                            product,
                            version,
                            len(data.get('vulnerabilities', [])),
                            matched_count,
                        )
                        vulnerabilities = data.get('vulnerabilities', [])
                        total_results = int(
                            data.get('totalResults', len(vulnerabilities))
                        )
                        next_start = page_start + len(vulnerabilities)
                        if vulnerabilities and next_start < total_results:
                            page_start = next_start
                            continue
                        break
                except NVDLookupError:
                    raise
                except Exception as exc:
                    logger.error("Error querying NVD keyword fallback: %s", exc)
                    retry_count += 1
                    if retry_count < self.max_retries:
                        await asyncio.sleep(delay)
                        delay *= 2
                    else:
                        raise NVDLookupError(
                            f"NVD keyword fallback failed after "
                            f"{self.max_retries} attempts for "
                            f"{product} {version}: {exc}"
                        ) from exc
            retry_count = 0

        if requests and not successful_requests:
            raise NVDLookupError(
                f"NVD returned no successful responses for "
                f"{vendor}:{product}:{version}"
            )
        return list(found_cves.values())

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
                'severity': metric.get('cvssData', {}).get('baseSeverity') or metric.get('baseSeverity'),
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
        results = CVECheckResults()
        unique_technologies = list(dict.fromkeys(technologies))
        if not unique_technologies:
            return results

        logger.info(
            "Checking CVEs for %s technologies",
            len(unique_technologies),
        )

        for name, version in unique_technologies:
            cache_key = f"{name}_{version}"
            try:
                cves = await self._get_or_start_lookup(cache_key, name, version)
            except NVDLookupError as exc:
                logger.error(
                    "NVD lookup failed for %s %s: %s",
                    name,
                    version,
                    exc,
                )
                continue

            results.completed_lookups.add(f"{name} ({version})")
            if cves:
                results[f"{name} ({version})"] = cves
                logger.info(
                    "NVD matched %s CVEs for %s %s",
                    len(cves), name, version,
                )
            else:
                logger.info("NVD matched 0 CVEs for %s %s", name, version)

        logger.info(
            "CVE check completed: %s technologies with CVEs found",
            len(results),
        )
        return results

    async def _get_or_start_lookup(
        self,
        cache_key: str,
        name: str,
        version: str,
    ) -> List[Dict]:
        async with self._cache_lock:
            cached_result = self._cache.get(cache_key)
            if cached_result:
                cache_ttl = cached_result.get(
                    'ttl',
                    self._cache_ttl
                    if cached_result.get('cves')
                    else self._negative_cache_ttl,
                )
                if time.time() - cached_result.get('timestamp', 0) < cache_ttl:
                    return cached_result.get('cves', [])

            task = self._inflight.get(cache_key)
            if task is None:
                task = asyncio.create_task(
                    self._query_and_cache(cache_key, name, version)
                )
                self._inflight[cache_key] = task

        return await asyncio.shield(task)

    async def _query_and_cache(
        self,
        cache_key: str,
        name: str,
        version: str,
    ) -> List[Dict]:
        try:
            cves = await self.check_cves_for_technology(name, version)
            self._cache[cache_key] = {
                'cves': cves,
                'timestamp': time.time(),
                'ttl': self._cache_ttl if cves else self._negative_cache_ttl,
            }
            return cves
        finally:
            async with self._cache_lock:
                self._inflight.pop(cache_key, None)
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("CVE checker HTTP session closed")
