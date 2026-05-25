import aiohttp
import asyncio
import json
import time
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
            
            self.rate_limiter = RateLimiter(rate=1.0, capacity=5) if rate_limit else None
        else:
            
            self.rate_limiter = RateLimiter(rate=50/30, capacity=5) if rate_limit else None

        
        self.max_retries = max_retries
        self.initial_delay = initial_delay

        
        self._cache: Dict[str, dict] = {}
        self._cache_ttl = 3600  
        
        
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
            'nginx': 'nginx',
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
            logger.debug(f"No vendor mapping found for {name}")
            return []

        
        cves = await self._query_nvd_api(vendor, name, version)

        
        if not cves and version != ".":
            version_parts = version.split('.')
            if len(version_parts) > 1:
                
                major_version = '.'.join(version_parts[:-1])
                if major_version:
                    logger.debug(f"Trying broader search for {name}:{major_version}")
                    cves = await self._query_nvd_api(vendor, name, major_version)

                
                if not cves and len(major_version.split('.')) > 1:
                    major_only = major_version.split('.')[0]
                    if major_only:
                        logger.debug(f"Trying broader search for {name}:{major_only}")
                        cves = await self._query_nvd_api(vendor, name, major_only)

        return cves

    async def _query_nvd_api(self, vendor: str, product: str, version: str) -> List[Dict]:
        
        cpe_match = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

        params = {
            "virtualMatchString": cpe_match,
            "resultsPerPage": 2000  
        }

        retry_count = 0
        delay = self.initial_delay

        while retry_count < self.max_retries:
            try:
                
                if self._session is None or self._session.closed:
                    self._session = aiohttp.ClientSession(headers=self.headers)
                
                async with self._session.get(self.nvd_base_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        cves = []

                        for item in data.get('vulnerabilities', []):
                            cve = item.get('cve', {})
                            cve_id = cve.get('id')

                            
                            descriptions = cve.get('descriptions', [])
                            description = next((desc['value'] for desc in descriptions if desc.get('lang') == 'en'), '')

                            
                            metrics = cve.get('metrics', {})
                            cvss_data = self._extract_cvss_data(metrics)

                            
                            published = cve.get('published')

                            
                            refs = cve.get('references', [])
                            reference_urls = [ref.get('url') for ref in refs if ref.get('url')]

                            cves.append({
                                'id': cve_id,
                                'description': description,
                                'cvss': cvss_data,
                                'published_date': published,
                                'last_modified': cve.get('lastModified'),
                                'references': reference_urls
                            })

                        return cves
                    elif response.status == 404:
                        
                        logger.debug(f"No CVEs found for {vendor}:{product}:{version} (status 404)")
                        return []
                    elif response.status == 429:
                        
                        logger.warning(f"NVD API rate limited (status 429), retrying in {delay}s...")
                        retry_count += 1
                        if retry_count < self.max_retries:
                            await asyncio.sleep(delay)
                            delay *= 2  
                        else:
                            logger.error(f"NVD API rate limited, max retries exceeded")
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
        
        
        if name_lower in self.vendor_mapping:
            return self.vendor_mapping[name_lower]
        
        
        for key, value in self.vendor_mapping.items():
            if key in name_lower or name_lower in key:
                return value
        
        
        return None

    async def check_cves_batch(self, technologies: List[Tuple[str, str]]) -> Dict[str, List[Dict]]:
        results = {}
        
        
        techs_to_check = []
        for name, version in technologies:
            cache_key = f"{name}_{version}"
            
            
            if cache_key in self._cache:
                cached_result = self._cache[cache_key]
                if time.time() - cached_result.get('timestamp', 0) < self._cache_ttl:
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
                    'timestamp': time.time()
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
