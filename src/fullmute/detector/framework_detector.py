from fullmute.detector.base import BaseDetector
from typing import Dict, List

class FrameworkDetector(BaseDetector):
    def detect(self):
        detected_frameworks = []

        if not self.signatures:
            return detected_frameworks

        for framework_name, patterns in self.signatures.items():
            if self._detect_single(framework_name, patterns):
                detected_frameworks.append(framework_name)

        return detected_frameworks

    def _detect_single(self, framework_name: str, patterns: Dict[str, List[str]]) -> bool:
        methods = [
            (self.search_in_headers, patterns.get("headers", [])),
            (self.search_in_html, patterns.get("html", [])),
        ]

        for method, pattern_list in methods:
            if pattern_list and method(pattern_list):
                return True

        return False
