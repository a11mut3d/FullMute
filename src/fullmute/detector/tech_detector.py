from typing import Dict, Any, List
from fullmute.detector.cms_detector import CMSDetector
from fullmute.detector.server_detector import ServerDetector
from fullmute.detector.framework_detector import FrameworkDetector
from fullmute.detector.camera_detector import CameraDetector
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
            "camera": []
        }

        if 'cms' in self.signatures:
            cms_detector = CMSDetector(
                self.url, self.headers, self.html, self.cookies,
                self.signatures['cms']
            )
            results["cms"] = cms_detector.detect()

        if 'server' in self.signatures:
            server_detector = ServerDetector(
                self.url, self.headers, self.html, self.cookies,
                self.signatures['server']
            )
            results["server"] = server_detector.detect()

        if 'framework' in self.signatures:
            framework_detector = FrameworkDetector(
                self.url, self.headers, self.html, self.cookies,
                self.signatures['framework']
            )
            results["framework"] = framework_detector.detect()

        if 'camera' in self.signatures:
            camera_detector = CameraDetector(
                url=self.url,
                html=self.html,
                headers=self.headers,
                signatures=self.signatures['camera']
            )
            results["camera"] = camera_detector.detect()

        filtered_results = {}
        for category, items in results.items():
            if items:
                filtered_results[category] = items

        return filtered_results
