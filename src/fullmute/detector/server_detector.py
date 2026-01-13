from fullmute.detector.base import BaseDetector
from typing import Dict, List

class ServerDetector(BaseDetector):
    def detect(self):
        detected_servers = []

        if not self.signatures:
            return detected_servers

        for server_name, patterns in self.signatures.items():
            if self._detect_single(server_name, patterns):
                detected_servers.append(server_name)

        return detected_servers

    def _detect_single(self, server_name: str, patterns: Dict[str, List[str]]) -> bool:
        methods = [
            (self.search_in_headers, patterns.get("headers", [])),
            (self.search_in_urls, patterns.get("urls", [])),
        ]

        for method, pattern_list in methods:
            if pattern_list and method(pattern_list):
                return True

        return False
