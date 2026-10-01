from fullmute.detector.base import BaseDetector
from typing import Dict, List, Any, Tuple
import re
from urllib.parse import parse_qs, unquote, urlsplit

class JSFrameworkDetector(BaseDetector):
    VERSIONED_LIBRARIES = {
        "jquery": ("jquery", "jquery-core"),
        "react": ("react", "react-dom"),
        "vue.js": ("vue",),
        "angular": ("angular", "angular.js"),
        "bootstrap": ("bootstrap",),
        "lodash": ("lodash",),
        "moment.js": ("moment",),
        "axios": ("axios",),
        "redux": ("redux",),
        "webpack": ("webpack",),
        "three.js": ("three",),
        "d3.js": ("d3",),
    }
    INLINE_VERSION_PATTERNS = {
        "jquery": r"jQuery(?:\s+JavaScript\s+Library)?\s+v?(\d+\.\d+(?:\.\d+){0,2})",
        "react": r"ReactVersion\s*[:=]\s*['\"](\d+\.\d+(?:\.\d+){0,2})['\"]",
        "vue.js": r"Vue(?:\.js)?\s+v(\d+\.\d+(?:\.\d+){0,2})",
        "angular": r"Angular(?:JS)?\s+v?(\d+\.\d+(?:\.\d+){0,2})",
        "bootstrap": r"Bootstrap\s+v(\d+\.\d+(?:\.\d+){0,2})",
        "lodash": r"lodash(?:\.js)?\s+v?(\d+\.\d+(?:\.\d+){0,2})",
        "moment.js": r"moment\.js\s+v?(\d+\.\d+(?:\.\d+){0,2})",
        "axios": r"axios\s+v(\d+\.\d+(?:\.\d+){0,2})",
        "redux": r"Redux\s+v(\d+\.\d+(?:\.\d+){0,2})",
        "webpack": r"webpack\s+v(\d+\.\d+(?:\.\d+){0,2})",
        "three.js": r"three\.js\s+r?(\d+\.\d+(?:\.\d+){0,2})",
        "d3.js": r"d3(?:\.js)?\s+v?(\d+\.\d+(?:\.\d+){0,2})",
    }

    def detect(self) -> List[Tuple[str, str]]:
        detected_js_libs = []

        if not self.signatures:
            return detected_js_libs

        for js_lib_name, patterns in self.signatures.items():
            if self._detect_single(js_lib_name, patterns):
                version = self._extract_version(js_lib_name, patterns)
                detected_js_libs.append((js_lib_name, version))

        return detected_js_libs

    def _detect_single(self, js_lib_name: str, patterns: Dict[str, Any]) -> bool:
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
            (self.search_in_js, patterns.get("js", []), 3),  
            (self.search_in_urls, patterns.get("urls", []), 1),
            (self.search_in_cookies, patterns.get("cookies", []), 2),
        ]

        for method, pattern_list, weight in methods:
            if pattern_list and method(pattern_list):
                score += weight
        required_score = 1 if must_have else 2

        return score >= required_score

    def _extract_version(self, js_lib_name: str, patterns: Dict[str, Any]) -> str:
        version_pattern = patterns.get("version_pattern", "")
        if version_pattern:
            version = self.extract_version_from_headers(version_pattern)
            if version:
                return version

            version = self.extract_version_from_html(version_pattern)
            if version:
                return version

        for asset_url in self._asset_urls():
            if version_pattern:
                version = self.extract_version(asset_url, version_pattern)
                if version:
                    return version
            version = self._extract_version_from_asset_url(js_lib_name, asset_url)
            if version:
                return version

        inline_pattern = self.INLINE_VERSION_PATTERNS.get(js_lib_name.casefold())
        if inline_pattern and self.html:
            match = re.search(inline_pattern, self.html, re.IGNORECASE)
            if match:
                return match.group(1)

        if version_pattern:
            version = self.extract_version_from_urls(version_pattern)
            if version:
                return version

            version = self.extract_version_from_cookies(version_pattern)
            if version:
                return version

        return ""

    def _asset_urls(self) -> List[str]:
        if not self.html:
            return []
        return re.findall(
            r'''<(?:script|link)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']''',
            self.html,
            re.IGNORECASE | re.DOTALL,
        )

    @classmethod
    def _extract_version_from_asset_url(cls, js_lib_name: str, asset_url: str) -> str:
        aliases = cls.VERSIONED_LIBRARIES.get(js_lib_name.casefold(), ())
        if not aliases:
            return ""

        decoded_url = unquote(asset_url)
        path = urlsplit(decoded_url).path
        path_segments = [segment for segment in path.split("/") if segment]
        alias_pattern = "|".join(re.escape(alias) for alias in aliases)
        version = r"v?(\d+\.\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.-]+)?)"
        patterns = (
            rf"(?:^|[/@])(?:{alias_pattern})@{version}(?=$|[/?.#])",
            rf"(?:^|/)(?:{alias_pattern})-{version}(?=$|[./_-])",
            rf"(?:^|/)(?:{alias_pattern})/{version}(?=$|/)",
        )
        for pattern in patterns:
            match = re.search(pattern, decoded_url, re.IGNORECASE)
            if match:
                return match.group(1)

        # Versioned WordPress assets commonly use ?ver=, ?version=, or ?v=.
        query = parse_qs(urlsplit(decoded_url).query)
        if re.search(rf"(?:^|[/_.-])(?:{alias_pattern})(?:[/_.-]|$)", path, re.IGNORECASE):
            for key in ("ver", "version", "v"):
                values = query.get(key, [])
                if values and re.fullmatch(
                    r"\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?",
                    values[0],
                ):
                    return values[0]

        # Some CDN URLs place the version directory just before the asset name.
        basename = path_segments[-1] if path_segments else ""
        if re.search(rf"(?:^|[-_.])(?:{alias_pattern})(?:[-_.]|$)", basename, re.IGNORECASE):
            for segment in reversed(path_segments[:-1]):
                if re.fullmatch(r"\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?", segment):
                    return segment
                if not re.fullmatch(r"(?:umd|cjs|esm|dist|build|min|production|development)", segment, re.IGNORECASE):
                    break

        return ""