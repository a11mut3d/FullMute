from fullmute.detector.base import BaseDetector
from typing import Dict, List, Any, Tuple

class CMSDetector(BaseDetector):
    def detect(self) -> List[Tuple[str, str]]:
        detected_cms = []

        if not self.signatures:
            return detected_cms

        for cms_name, patterns in self.signatures.items():
            if self._detect_single(cms_name, patterns):
                version = self._extract_version(cms_name, patterns)
                detected_cms.append((cms_name, version))

        return detected_cms

    def _detect_single(self, cms_name: str, patterns: Dict[str, Any]) -> bool:
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

    def _extract_version(self, cms_name: str, patterns: Dict[str, Any]) -> str:
        version_pattern = patterns.get("version_pattern", "")
        if not version_pattern:
            return ""

        
        version = self.extract_version_from_headers(version_pattern)
        if version:
            return version

        version = self.extract_version_from_html(version_pattern)
        if version:
            return version

        version = self.extract_version_from_urls(version_pattern)
        if version:
            return version

        version = self.extract_version_from_cookies(version_pattern)
        if version:
            return version

        return ""
