import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple
from fullmute.utils.logger import setup_logger

logger = setup_logger()


class BaseDetector(ABC):
    def __init__(self, url: str, headers: Dict[str, str], html: str,
                 cookies: Dict[str, str], signatures: Dict[str, Any]):
        self.url = url or ""
        self.headers = headers or {}
        self.html = html or ""
        self.cookies = cookies or {}
        self.signatures = signatures or {}

    @abstractmethod
    def detect(self) -> List[str]:
        pass

    # ------------------------------------------------------------------ #
    # Safe regex helpers
    # ------------------------------------------------------------------ #
    def _compile(self, pattern: str):
        """Compile pattern once, cache by string. Returns None on bad regex."""
        cache = self.__dict__.setdefault("_regex_cache", {})
        if pattern in cache:
            return cache[pattern]
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            logger.warning(f"Bad regex {pattern!r}: {e}")
            compiled = None
        cache[pattern] = compiled
        return compiled

    def _safe_search(self, pattern: str, text: str) -> bool:
        if not text:
            return False
        compiled = self._compile(pattern)
        if compiled is None:
            return False
        return compiled.search(text) is not None

    def _safe_findall(self, pattern: str, text: str) -> List[str]:
        if not text:
            return []
        compiled = self._compile(pattern)
        if compiled is None:
            return []
        return compiled.findall(text)

    # ------------------------------------------------------------------ #
    # Generic search helpers (pattern lists are regexes)
    # ------------------------------------------------------------------ #
    def search_in_headers(self, patterns: List[str]) -> bool:
        for header_name, header_value in self.headers.items():
            header_string = f"{header_name}: {header_value}"
            for pattern in patterns:
                if self._safe_search(pattern, header_string):
                    return True
        return False

    def search_in_html(self, patterns: List[str]) -> bool:
        if not self.html:
            return False
        for pattern in patterns:
            if self._safe_search(pattern, self.html):
                return True
        return False

    def search_in_js(self, patterns: List[str]) -> bool:
        if not self.html:
            return False
        script_srcs = self._safe_findall(r'<script[^>]*src=["\']([^"\']+)["\']', self.html)
        for pattern in patterns:
            for src in script_srcs:
                if self._safe_search(pattern, src):
                    return True
        return False

    def search_in_paths(self, patterns: List[str]) -> bool:
        if not self.html:
            return False
        resources = self._safe_findall(r'(?:href|src)=["\']([^"\']+)["\']', self.html)
        for pattern in patterns:
            for res in resources:
                if self._safe_search(pattern, res):
                    return True
        return False

    def search_in_cookies(self, patterns: List[str]) -> bool:
        for cookie_name in self.cookies.keys():
            for pattern in patterns:
                if self._safe_search(pattern, cookie_name):
                    return True
        return False

    def search_in_csp(self, patterns: List[str]) -> bool:
        csp = self.headers.get("Content-Security-Policy", "")
        if not csp:
            return False
        for pattern in patterns:
            if self._safe_search(pattern, csp):
                return True
        return False

    def search_in_title(self, patterns: List[str]) -> bool:
        if not self.html:
            return False
        m = re.search(r"<title[^>]*>(.*?)</title>", self.html, re.IGNORECASE | re.DOTALL)
        if not m:
            return False
        title = m.group(1)
        for pattern in patterns:
            if self._safe_search(pattern, title):
                return True
        return False

    def search_in_scripts(self, patterns: List[str]) -> bool:
        if not self.html:
            return False
        script_srcs = self._safe_findall(r'<script[^>]*src=["\']([^"\']+)["\']', self.html)
        for pattern in patterns:
            for src in script_srcs:
                if self._safe_search(pattern, src):
                    return True
        return False

    def search_in_favicon(self, patterns: List[str]) -> bool:
        if not self.html:
            return False
        icons = self._safe_findall(
            r'<link[^>]*rel=["\'](?:icon|shortcut icon)["\'][^>]*href=["\']([^"\']+)["\']',
            self.html,
        )
        for pattern in patterns:
            for icon_url in icons:
                if self._safe_search(pattern, icon_url):
                    return True
        return False

    def search_in_meta(self, patterns: List[str]) -> bool:
        if not self.html:
            return False
        meta_tags = self._safe_findall(r"<meta[^>]+>", self.html)
        for meta in meta_tags:
            for pattern in patterns:
                if self._safe_search(pattern, meta):
                    return True
        return False

    def search_in_urls(self, patterns: List[str]) -> bool:
        for pattern in patterns:
            if self._safe_search(pattern, self.url):
                return True
        return False

    # ------------------------------------------------------------------ #
    # must_have / must_not_have
    #
    # must_have semantics: ANY of the patterns must be found.
    #   If the signature author wants AND, they should express it in a
    #   single combined regex, or add a dedicated field (not supported here).
    #
    # must_not_have semantics: NONE of the patterns may be found.
    # ------------------------------------------------------------------ #
    def check_must_have(self, must_have_patterns: List[str]) -> bool:
        if not must_have_patterns:
            return True
        for pattern in must_have_patterns:
            if (self.search_in_html([pattern]) or
                    self.search_in_headers([pattern]) or
                    self.search_in_urls([pattern]) or
                    self.search_in_paths([pattern]) or
                    self.search_in_meta([pattern]) or
                    self.search_in_title([pattern])):
                return True
        return False

    def check_must_not_have(self, must_not_have_patterns: List[str]) -> bool:
        if not must_not_have_patterns:
            return True
        for pattern in must_not_have_patterns:
            if (self.search_in_html([pattern]) or
                    self.search_in_headers([pattern]) or
                    self.search_in_meta([pattern]) or
                    self.search_in_title([pattern])):
                return False
        return True

    # ------------------------------------------------------------------ #
    # Version extraction
    # ------------------------------------------------------------------ #
    def extract_version(self, content: str, version_pattern: str) -> str:
        if not version_pattern or not content:
            return ""
        compiled = self._compile(version_pattern)
        if compiled is None:
            return ""
        m = compiled.search(content)
        if m:
            # Return first capturing group if any, else whole match
            if m.groups():
                return m.group(1)
            return m.group(0)
        return ""

    def extract_version_from_headers(self, version_pattern: str) -> str:
        for header_name, header_value in self.headers.items():
            header_string = f"{header_name}: {header_value}"
            v = self.extract_version(header_string, version_pattern)
            if v:
                return v
        return ""

    def extract_version_from_html(self, version_pattern: str) -> str:
        return self.extract_version(self.html, version_pattern)

    def extract_version_from_urls(self, version_pattern: str) -> str:
        return self.extract_version(self.url, version_pattern)

    def extract_version_from_paths(self, version_pattern: str) -> str:
        if not self.html:
            return ""
        resources = self._safe_findall(r'(?:href|src)=["\']([^"\']+)["\']', self.html)
        for res in resources:
            v = self.extract_version(res, version_pattern)
            if v:
                return v
        return ""

    def extract_version_from_meta(self, version_pattern: str) -> str:
        if not self.html:
            return ""
        contents = self._safe_findall(r'<meta[^>]+content=["\']([^"\']+)["\']', self.html)
        for content in contents:
            v = self.extract_version(content, version_pattern)
            if v:
                return v
        return ""

    def extract_version_from_cookies(self, version_pattern: str) -> str:
        for cookie_name in self.cookies.keys():
            v = self.extract_version(cookie_name, version_pattern)
            if v:
                return v
        return ""
