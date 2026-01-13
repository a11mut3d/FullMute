import re
from typing import List, Dict, Any
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class CameraDetector:
    def __init__(self, url: str, html: str, headers: Dict[str, str], signatures: Dict[str, Any]):
        self.url = url
        self.html = html
        self.headers = headers
        self.signatures = signatures

    def detect(self) -> List[str]:
        detected_cameras = []

        if not self.signatures:
            return detected_cameras

        for camera_name, patterns in self.signatures.items():
            if self._detect_single(camera_name, patterns):
                detected_cameras.append(camera_name)

        return detected_cameras

    def _detect_single(self, camera_name: str, patterns: Dict[str, List[str]]) -> bool:
        score = 0

        if patterns.get("headers"):
            for header_pattern in patterns["headers"]:
                for header_name, header_value in self.headers.items():
                    header_string = f"{header_name}: {header_value}"
                    if re.search(header_pattern, header_string, re.IGNORECASE):
                        score += 2
                        break

        if patterns.get("html") and self.html:
            for html_pattern in patterns["html"]:
                if re.search(html_pattern, self.html, re.IGNORECASE):
                    score += 1

        if patterns.get("titles") and self.html:
            title_match = re.search(r'<title>(.*?)</title>', self.html, re.IGNORECASE)
            if title_match:
                title = title_match.group(1)
                for title_pattern in patterns["titles"]:
                    if re.search(title_pattern, title, re.IGNORECASE):
                        score += 2

        if patterns.get("favicon") and self.html:
            for favicon_pattern in patterns["favicon"]:
                favicon_regex = r'<link[^>]*href=["\'][^"\']*' + favicon_pattern.replace('.', '\\.') + r'["\'][^>]*>'
                if re.search(favicon_regex, self.html, re.IGNORECASE):
                    score += 2

        if patterns.get("must_not_have") and self.html:
            for exclude_pattern in patterns["must_not_have"]:
                if re.search(exclude_pattern, self.html, re.IGNORECASE):
                    return False

        required_score = patterns.get("confidence", 2)
        return score >= required_score
