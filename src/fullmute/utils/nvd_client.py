import aiohttp
import asyncio
import json
from typing import Dict, List, Optional
from datetime import datetime
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class NVDClient:
    """
    Client for interacting with the NVD (National Vulnerability Database) API
    """
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.headers = {
            "Accept": "application/json"
        }
        if api_key:
            self.headers["apiKey"] = api_key
    
    async def search_cve_by_product(self, vendor: str, product: str, version: str = None) -> List[Dict]:
        """
        Search for CVEs by vendor, product, and optionally version
        """
        params = {
            "cpeName": f"cpe:2.3:a:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*" if version 
                      else f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
        }
        
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(self.BASE_URL, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('vulnerabilities', [])
                    else:
                        logger.error(f"NVD API request failed with status {response.status}")
                        return []
        except Exception as e:
            logger.error(f"Error querying NVD API: {e}")
            return []
    
    async def search_cve_by_cpe(self, cpe_string: str) -> List[Dict]:
        """
        Search for CVEs by CPE string
        """
        params = {
            "cpeName": cpe_string
        }
        
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(self.BASE_URL, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('vulnerabilities', [])
                    else:
                        logger.error(f"NVD API request failed with status {response.status}")
                        return []
        except Exception as e:
            logger.error(f"Error querying NVD API: {e}")
            return []
    
    def extract_cve_info(self, cve_data: Dict) -> Dict:
        """
        Extract relevant information from CVE data
        """
        cve_item = cve_data.get('cve', {})
        
        
        cvss_data = {}
        metrics = cve_item.get('metrics', {})
        
        
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_metric = metrics['cvssMetricV31'][0]
            cvss_data = {
                'version': '3.1',
                'score': cvss_metric.get('cvssData', {}).get('baseScore'),
                'severity': cvss_metric.get('cvssData', {}).get('baseSeverity'),
                'vector': cvss_metric.get('cvssData', {}).get('vectorString')
            }
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_metric = metrics['cvssMetricV30'][0]
            cvss_data = {
                'version': '3.0',
                'score': cvss_metric.get('cvssData', {}).get('baseScore'),
                'severity': cvss_metric.get('cvssData', {}).get('baseSeverity'),
                'vector': cvss_metric.get('cvssData', {}).get('vectorString')
            }
        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_metric = metrics['cvssMetricV2'][0]
            cvss_data = {
                'version': '2.0',
                'score': cvss_metric.get('cvssData', {}).get('baseScore'),
                'severity': cvss_metric.get('baseSeverity'),
                'vector': cvss_metric.get('cvssData', {}).get('vectorString')
            }
        
        
        descriptions = cve_item.get('descriptions', [])
        description = next((desc['value'] for desc in descriptions if desc.get('lang') == 'en'), '')
        
        return {
            'id': cve_item.get('id'),
            'description': description,
            'published_date': cve_item.get('published'),
            'last_modified': cve_item.get('lastModified'),
            'cvss': cvss_data,
            'references': cve_item.get('references', [])
        }


async def test_nvd_client():
    """
    Test function for NVD client
    """
    client = NVDClient()
    
    
    cves = await client.search_cve_by_product("microsoft", "internet_explorer", "8.0")
    print(f"Found {len(cves)} CVEs for Microsoft Internet Explorer 8.0")
    
    if cves:
        cve_info = client.extract_cve_info(cves[0])
        print(f"CVE ID: {cve_info['id']}")
        print(f"Description: {cve_info['description'][:100]}...")
        print(f"CVSS Score: {cve_info['cvss'].get('score')}")
        print(f"Severity: {cve_info['cvss'].get('severity')}")


if __name__ == "__main__":
    asyncio.run(test_nvd_client())