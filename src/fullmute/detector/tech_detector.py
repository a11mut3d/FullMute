from typing import Dict, Any, List
from fullmute.detector.cms_detector import CMSDetector
from fullmute.detector.server_detector import ServerDetector
from fullmute.detector.framework_detector import FrameworkDetector
from fullmute.detector.camera_detector import CameraDetector
from fullmute.detector.router_detector import RouterDetector
from fullmute.detector.js_framework_detector import JSFrameworkDetector
from fullmute.detector.database_detector import DatabaseDetector
from fullmute.detector.language_detector import LanguageDetector
from fullmute.detector.plugin_detector import PluginDetector
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class TechDetector:
    def __init__(self, url: str, headers: Dict[str, str], html: str, cookies: Dict[str, str], signatures: Dict[str, Any]):
        self.url = url
        self.headers = headers
        self.html = html
        self.cookies = cookies
        self.signatures = signatures

        logger.debug(f"TechDetector initialized for {url}")

    def detect(self) -> Dict[str, List[str]]:
        results = {
            "cms": [],
            "server": [],
            "framework": [],
            "camera": [],
            "router": [],
            "javascript": [],
            "database": [],
            "language": [],
            "plugins": [],
            "themes": []
        }

        if 'cms' in self.signatures:
            cms_detector = CMSDetector(
                self.url, self.headers, self.html, self.cookies,
                self.signatures['cms']
            )
            cms_results = cms_detector.detect()
            results["cms"] = [f"{name} ({version})" if version else name for name, version in cms_results]

        if 'server' in self.signatures:
            server_detector = ServerDetector(
                self.url, self.headers, self.html, self.cookies,
                self.signatures['server']
            )
            server_results = server_detector.detect()
            results["server"] = [f"{name} ({version})" if version else name for name, version in server_results]

        if 'framework' in self.signatures:
            framework_detector = FrameworkDetector(
                self.url, self.headers, self.html, self.cookies,
                self.signatures['framework']
            )
            framework_results = framework_detector.detect()
            results["framework"] = [f"{name} ({version})" if version else name for name, version in framework_results]

        if 'camera' in self.signatures:
            camera_detector = CameraDetector(
                url=self.url,
                html=self.html,
                headers=self.headers,
                signatures=self.signatures['camera']
            )
            camera_results = camera_detector.detect()
            results["camera"] = [f"{name} ({version})" if version else name for name, version in camera_results]

        if 'router' in self.signatures:
            router_detector = RouterDetector(
                self.url, self.headers, self.html, self.cookies,
                self.signatures['router']
            )
            router_results = router_detector.detect()
            results["router"] = [f"{name} ({version})" if version else name for name, version in router_results]

        if 'js_framework' in self.signatures:
            js_framework_detector = JSFrameworkDetector(
                self.url, self.headers, self.html, self.cookies,
                self.signatures['js_framework']
            )
            js_results = js_framework_detector.detect()
            results["javascript"] = [f"{name} ({version})" if version else name for name, version in js_results]

        if 'database' in self.signatures:
            database_detector = DatabaseDetector(
                self.url, self.headers, self.html, self.cookies,
                self.signatures['database']
            )
            database_results = database_detector.detect()
            results["database"] = [f"{name} ({version})" if version else name for name, version in database_results]

        if 'language' in self.signatures:
            language_detector = LanguageDetector(
                self.url, self.headers, self.html, self.cookies,
                self.signatures['language']
            )
            language_results = language_detector.detect()
            results["language"] = [f"{name} ({version})" if version else name for name, version in language_results]

        
        plugin_detector = PluginDetector(
            url=self.url,
            headers=self.headers,
            html=self.html
        )
        plugin_results = plugin_detector.detect_plugins()

        
        for cms_type, items in plugin_results.items():
            if cms_type == 'wordpress_themes':
                results["themes"] = [f"{name} ({version})" if version else name for name, version in items]
            elif cms_type in ['wordpress', 'joomla', 'drupal']:
                results["plugins"] = [f"{name} ({version})" if version else name for name, version in items]
                
                if cms_type == 'wordpress':
                    results["wp_plugins"] = [f"{name} ({version})" if version else name for name, version in items]

        filtered_results = {}
        for category, items in results.items():
            if items:
                filtered_results[category] = items

        return filtered_results
