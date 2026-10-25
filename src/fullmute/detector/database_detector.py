import re
from typing import Dict, List, Any, Tuple

from fullmute.detector.base import BaseDetector
from fullmute.utils.logger import setup_logger

logger = setup_logger()


class DatabaseDetector(BaseDetector):
    # Threshold when must_have is present (must_have already gives a strong signal).
    THRESHOLD_WITH_MUST_HAVE = 2
    # Threshold when must_have is absent (need more independent evidence).
    THRESHOLD_WITHOUT_MUST_HAVE = 3

    def detect(self) -> List[Tuple[str, str]]:
        detected: List[Tuple[str, str]] = []
        if not self.signatures:
            logger.debug("DatabaseDetector: empty signatures")
            return detected

        for db_name, patterns in self.signatures.items():
            try:
                if self._detect_single(db_name, patterns):
                    version = self._extract_version(db_name, patterns)
                    detected.append((db_name, version))
            except Exception as e:
                logger.exception(f"[{db_name}] detection error: {e}")
        return detected

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    def _detect_single(self, db_name: str, patterns: Dict[str, Any]) -> bool:
        must_not_have = patterns.get("must_not_have", []) or []
        if must_not_have and not self.check_must_not_have(must_not_have):
            logger.debug(f"[{db_name}] rejected by must_not_have")
            return False

        must_have = patterns.get("must_have", []) or []
        if must_have and not self.check_must_have(must_have):
            logger.debug(f"[{db_name}] rejected by must_have")
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

        threshold = (
            self.THRESHOLD_WITH_MUST_HAVE
            if must_have
            else self.THRESHOLD_WITHOUT_MUST_HAVE
        )
        logger.debug(f"[{db_name}] score={score} threshold={threshold}")
        return score >= threshold

    # ------------------------------------------------------------------ #
    # Version extraction
    # ------------------------------------------------------------------ #
    def _extract_version(self, db_name: str, patterns: Dict[str, Any]) -> str:
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
                logger.warning(f"[{db_name}] version extractor {extractor.__name__} failed: {e}")
                continue
            if v:
                return v
        return ""
