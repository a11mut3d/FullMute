import re
from typing import Dict, List, Any, Tuple

from fullmute.detector.base import BaseDetector
from fullmute.utils.logger import setup_logger

logger = setup_logger()


class LanguageDetector(BaseDetector):
    # Minimum score to accept a language when must_have is empty.
    # When must_have is non-empty, passing it already gives a strong signal,
    # so a lower threshold is fine.
    THRESHOLD_WITH_MUST_HAVE = 2
    THRESHOLD_WITHOUT_MUST_HAVE = 3

    def detect(self) -> List[Tuple[str, str]]:
        detected: List[Tuple[str, str]] = []
        if not self.signatures:
            logger.debug("LanguageDetector: empty signatures")
            return detected

        for lang_name, patterns in self.signatures.items():
            try:
                if self._detect_single(lang_name, patterns):
                    version = self._extract_version(lang_name, patterns)
                    detected.append((lang_name, version))
            except Exception as e:
                logger.exception(f"[{lang_name}] detection error: {e}")
        return detected

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    def _detect_single(self, lang_name: str, patterns: Dict[str, Any]) -> bool:
        must_not_have = patterns.get("must_not_have", []) or []
        if must_not_have and not self.check_must_not_have(must_not_have):
            return False

        must_have = patterns.get("must_have", []) or []
        if must_have and not self.check_must_have(must_have):
            return False

        score = 0

        # Weighted evidence. Each source counted at most once.
        if patterns.get("headers") and self.search_in_headers(patterns["headers"]):
            score += 2
        if patterns.get("cookies") and self.search_in_cookies(patterns["cookies"]):
            score += 2
        if patterns.get("html") and self.search_in_html(patterns["html"]):
            score += 1
        if patterns.get("html") and self.search_in_meta(patterns["html"]):
            score += 1
        if patterns.get("html") and self.search_in_title(patterns["html"]):
            score += 1
        if patterns.get("html") and self.search_in_scripts(patterns["html"]):
            score += 1
        if patterns.get("html") and self.search_in_favicon(patterns["html"]):
            score += 1

        # URL evidence: count once, whether it matches self.url or resources.
        url_patterns = patterns.get("urls", []) or []
        if url_patterns:
            if self.search_in_urls(url_patterns) or self.search_in_paths(url_patterns):
                score += 2

        # File-extension evidence inside HTML (e.g. "index.php" mentioned in body)
        if self.html and url_patterns:
            has_ext_pattern = any(
                ext in str(up).lower()
                for up in url_patterns
                for ext in (".php", ".aspx", ".jsp", ".jspx", ".asp")
            )
            if has_ext_pattern:
                try:
                    if re.search(
                        r"(index\.php|\.php\b|\.aspx\b|\.jsp\b|\.jspx\b|\.asp\b)",
                        self.html, re.IGNORECASE,
                    ):
                        score += 1
                except re.error:
                    pass

        threshold = (
            self.THRESHOLD_WITH_MUST_HAVE
            if must_have
            else self.THRESHOLD_WITHOUT_MUST_HAVE
        )
        logger.debug(f"[{lang_name}] score={score} threshold={threshold}")
        return score >= threshold

    # ------------------------------------------------------------------ #
    # Version extraction — try every source, not just headers/html/urls/cookies
    # ------------------------------------------------------------------ #
    def _extract_version(self, lang_name: str, patterns: Dict[str, Any]) -> str:
        version_pattern = patterns.get("version_pattern", "")
        if not version_pattern:
            return ""

        extractors = (
            self.extract_version_from_headers,
            self.extract_version_from_urls,
            self.extract_version_from_paths,
            self.extract_version_from_meta,
            self.extract_version_from_html,
            self.extract_version_from_cookies,
        )
        for extractor in extractors:
            try:
                v = extractor(version_pattern)
            except Exception as e:
                logger.warning(f"[{lang_name}] version extractor {extractor.__name__} failed: {e}")
                continue
            if v:
                return v
        return ""
