import re
from fullmute.detector.base import BaseDetector
from typing import Dict, List, Any, Tuple

class RouterDetector(BaseDetector):
    def detect(self) -> List[Tuple[str, str]]:
        detected_routers = []

        if not self.signatures:
            return detected_routers

        for router_name, patterns in self.signatures.items():
            if self._detect_single(router_name, patterns):
                version = self._extract_version(router_name, patterns)
                detected_routers.append((router_name, version))

        return detected_routers

    def _detect_single(self, router_name: str, patterns: Dict[str, Any]) -> bool:
        must_not_have = patterns.get("must_not_have", [])
        if must_not_have and not self.check_must_not_have(must_not_have):
            return False
        must_have = patterns.get("must_have", [])
        # For routers allow detection when any identifying marker is present (not all)
        if must_have:
            found_any = False
            for p in must_have:
                if self.search_in_html([p]) or self.search_in_headers([p]) or self.search_in_urls([p]) or self.search_in_paths([p]):
                    found_any = True
                    break
            if not found_any:
                return False

        score = 0
        methods = [
            (self.search_in_headers, patterns.get("headers", []), 3),
            (self.search_in_html, patterns.get("html", []), 2),
            (self.search_in_urls, patterns.get("urls", []), 2),
            (self.search_in_cookies, patterns.get("cookies", []), 2),
            (self.search_in_js, patterns.get("scripts", []), 1),
            (self.search_in_paths, patterns.get("paths", []) or patterns.get("html", []), 1),
            (self.search_in_csp, patterns.get("csp", []), 1),
            (self.search_in_title, patterns.get("titles", []) or patterns.get("html", []), 1),
            (self.search_in_meta, patterns.get("meta", []), 1),
            (self.search_in_favicon, patterns.get("favicon", []), 1),
        ]

        # Check html-patterns inside headers too (CSP may reference vendor domains)
        headers_combined = ' '.join(f"{k}: {v}" for k, v in self.headers.items() if v)
        header_html_match = False
        for pat in patterns.get("html", []):
            try:
                if re.search(pat, headers_combined, re.IGNORECASE):
                    header_html_match = True
                    break
            except re.error:
                if pat.lower() in headers_combined.lower():
                    header_html_match = True
                    break

        for method, pattern_list, weight in methods:
            if pattern_list and method(pattern_list):
                score += weight

        if header_html_match:
            score += 1

        # Detect simple JS redirects that set window.location or location.href
        try:
            if self.html:
                m = re.search(r"window\.location(?:\.pathname)?\s*=\s*['\"]([^'\"]+)['\"]", self.html)
                if not m:
                    m = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", self.html)
                if m:
                    redirect_path = m.group(1)
                    for pat in patterns.get("html", []):
                        if re.search(pat, redirect_path, re.IGNORECASE):
                            score += 1
                            break
        except Exception:
            pass

        required_score = 1 if must_have else 2

        return score >= required_score

    def _extract_version(self, router_name: str, patterns: Dict[str, Any]) -> str:
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
