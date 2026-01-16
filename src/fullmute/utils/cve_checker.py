import aiohttp
import asyncio
import json
from typing import Dict, List, Optional, Tuple
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class CVEChecker:
    """
    Module for checking CVEs for detected technologies
    """
    def __init__(self, nvd_api_key: Optional[str] = None):
        self.nvd_api_key = nvd_api_key
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {
            "Accept": "application/json"
        }
        if self.nvd_api_key:
            self.headers["apiKey"] = self.nvd_api_key

        # Vendor mapping for common technologies
        self.vendor_mapping = {
            # CMS
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
            
            # Frameworks
            'laravel': 'laravel',
            'django': 'djangoproject',
            'ruby on rails': 'ruby-on-rails',
            'express.js': 'expressjs',
            'spring boot': 'spring-framework',
            'symfony': 'symfony',
            'yii': 'yiiframework',
            'codeigniter': 'codeigniter',
            'flask': 'pallets',
            
            # Web Servers
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
            
            # Routers
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
            
            # Cameras
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
            
            # JS Libraries
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
            
            # Databases
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'mongodb': 'mongodb',
            'redis': 'redis',
            'sqlite': 'sqlite',
            'oracle': 'oracle',
            'microsoft sql server': 'microsoft',
            
            # Languages
            'php': 'php',
            'python': 'python',
            'java': 'oracle',
            'node.js': 'nodejs',
            'ruby': 'ruby-lang',
            'go': 'golang',
            'c#': 'microsoft',
            'perl': 'perl',
            
            # Plugins
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

        # Map technology name to vendor
        vendor = self._map_vendor(name)
        if not vendor:
            logger.debug(f"No vendor mapping found for {name}")
            return []

        # Query NVD API for CVEs
        cves = await self._query_nvd_api(vendor, name, version)

        # If no CVEs found for exact version, try broader search
        if not cves and version != ".":
            version_parts = version.split('.')
            if len(version_parts) > 1:
                # Try with major version only (e.g., 6.8.3 -> 6.8)
                major_version = '.'.join(version_parts[:-1])
                if major_version:
                    logger.debug(f"Trying broader search for {name}:{major_version}")
                    cves = await self._query_nvd_api(vendor, name, major_version)

                # If still no CVEs, try with major version only (e.g., 6.8 -> 6)
                if not cves and len(major_version.split('.')) > 1:
                    major_only = major_version.split('.')[0]
                    if major_only:
                        logger.debug(f"Trying broader search for {name}:{major_only}")
                        cves = await self._query_nvd_api(vendor, name, major_only)

        return cves

    async def _query_nvd_api(self, vendor: str, product: str, version: str) -> List[Dict]:
        try:
            # Construct CPE string
            cpe_match = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

            params = {
                "virtualMatchString": cpe_match,
                "resultsPerPage": 2000  # Maximum allowed
            }

            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(self.nvd_base_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        cves = []

                        for item in data.get('vulnerabilities', []):
                            cve = item.get('cve', {})
                            cve_id = cve.get('id')

                            # Extract description
                            descriptions = cve.get('descriptions', [])
                            description = next((desc['value'] for desc in descriptions if desc.get('lang') == 'en'), '')

                            # Extract metrics (CVSS scores)
                            metrics = cve.get('metrics', {})
                            cvss_data = self._extract_cvss_data(metrics)

                            # Extract published date
                            published = cve.get('published')

                            # Extract references
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
                        # 404 может означать, что для данной версии нет CVE
                        logger.debug(f"No CVEs found for {vendor}:{product}:{version} (status 404)")
                        return []
                    else:
                        logger.error(f"NVD API request failed with status {response.status}")
                        return []
        except Exception as e:
            logger.error(f"Error querying NVD API: {e}")
            return []

    def _extract_cvss_data(self, metrics: Dict) -> Dict:
        cvss_data = {}
        
        # Check for CVSS v3.1
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            metric = metrics['cvssMetricV31'][0]
            cvss_data = {
                'version': '3.1',
                'score': metric.get('cvssData', {}).get('baseScore'),
                'severity': metric.get('cvssData', {}).get('baseSeverity'),
                'vector': metric.get('cvssData', {}).get('vectorString')
            }
        # Check for CVSS v3.0
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            metric = metrics['cvssMetricV30'][0]
            cvss_data = {
                'version': '3.0',
                'score': metric.get('cvssData', {}).get('baseScore'),
                'severity': metric.get('cvssData', {}).get('baseSeverity'),
                'vector': metric.get('cvssData', {}).get('vectorString')
            }
        # Check for CVSS v2
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
        
        # Direct match
        if name_lower in self.vendor_mapping:
            return self.vendor_mapping[name_lower]
        
        # Partial match
        for key, value in self.vendor_mapping.items():
            if key in name_lower or name_lower in key:
                return value
        
        # If no match found, return None
        return None

    async def check_cves_batch(self, technologies: List[Tuple[str, str]]) -> Dict[str, List[Dict]]:
        results = {}
        
        # Process in batches to avoid overwhelming the API
        batch_size = 5  # Conservative limit
        
        for i in range(0, len(technologies), batch_size):
            batch = technologies[i:i + batch_size]
            
            # Process each technology in the batch
            for name, version in batch:
                cves = await self.check_cves_for_technology(name, version)
                if cves:
                    results[f"{name} ({version})"] = cves
            
            # Small delay between batches to be respectful to the API
            if i + batch_size < len(technologies):
                await asyncio.sleep(1)
        
        return results
