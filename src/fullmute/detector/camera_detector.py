import logging
import re
from typing import List, Dict, Any, Tuple
from fullmute.detector.base import BaseDetector

logger = logging.getLogger('fullmute')

class CameraDetector(BaseDetector):
    def __init__(self, url: str, html: str, headers: Dict[str, str], cookies: Dict[str, str], signatures: Dict[str, Any]):
        # Инициализируем с пустым html, headers, cookies, но передаем нужные значения
        super().__init__(url, headers, html, cookies, signatures)

    def detect(self) -> List[Tuple[str, str]]:
        detected_cameras = []

        if not self.signatures:
            return detected_cameras

        for camera_name, patterns in self.signatures.items():
            if self._detect_single(camera_name, patterns):
                version = self._extract_version(camera_name, patterns)
                detected_cameras.append((camera_name, version))

        return detected_cameras

    def _detect_single(self, camera_name: str, patterns: Dict[str, Any]) -> bool:
        must_not_have = patterns.get("must_not_have", [])
        if must_not_have and not self.check_must_not_have(must_not_have):
            return False
        must_have = patterns.get("must_have", [])
        if must_have and not self.check_must_have(must_have):
            return False

        score = 0
        methods = [
            (self.search_in_headers, patterns.get("headers", []), 2),
            (self.search_in_html, patterns.get("html", []), 1),
            (self.search_in_urls, patterns.get("urls", []), 1),
            (self.search_in_cookies, patterns.get("cookies", []), 2),
        ]

        for method, pattern_list, weight in methods:
            if pattern_list and method(pattern_list):
                score += weight
        required_score = 1 if must_have else 2

        return score >= required_score

    def _extract_version(self, camera_name: str, patterns: Dict[str, Any]) -> str:
        version_pattern = patterns.get("version_pattern", "")
        if not version_pattern:
            return ""

        
        for header_name, header_value in self.headers.items():
            header_string = f"{header_name}: {header_value}"
            version = self._extract_version_from_content(header_string, version_pattern)
            if version:
                return version

        
        if self.html:
            version = self._extract_version_from_content(self.html, version_pattern)
            if version:
                return version

        return ""

    def _extract_version_from_content(self, content: str, version_pattern: str) -> str:
        """Extract version from content using the provided pattern"""
        if not version_pattern:
            return ""

        match = re.search(version_pattern, content, re.IGNORECASE)
        if match:
            return match.group(1)  
        return ""
