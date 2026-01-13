import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseDetector(ABC):
    def __init__(self, url: str, headers: Dict[str, str], html: str, cookies: Dict[str, str], signatures: Dict[str, Any]):
        self.url = url
        self.headers = headers
        self.html = html
        self.cookies = cookies
        self.signatures = signatures

    @abstractmethod
    def detect(self) -> List[str]:
        pass

    def search_in_headers(self, patterns: List[str]) -> bool:
        for header_name, header_value in self.headers.items():
            header_string = f"{header_name}: {header_value}"
            for pattern in patterns:
                if re.search(pattern, header_string, re.IGNORECASE):
                    return True
        return False

    def search_in_html(self, patterns: List[str]) -> bool:
        if not self.html:
            return False

        for pattern in patterns:
            if re.search(pattern, self.html, re.IGNORECASE):
                return True
        return False

    def search_in_js(self, patterns: List[str]) -> bool:
        if not self.html:
            return False

        script_patterns = re.findall(r'<script.*?src=["\'](.*?)["\']', self.html)
        for pattern in patterns:
            for script in script_patterns:
                if re.search(pattern, script, re.IGNORECASE):
                    return True
        return False

    def search_in_cookies(self, patterns: List[str]) -> bool:
        for cookie_name in self.cookies.keys():
            for pattern in patterns:
                if re.search(pattern, cookie_name, re.IGNORECASE):
                    return True
        return False

    def search_in_urls(self, patterns: List[str]) -> bool:
        for pattern in patterns:
            if re.search(pattern, self.url, re.IGNORECASE):
                return True
        return False

    def check_must_have(self, must_have_patterns: List[str]) -> bool:
        if not must_have_patterns:
            return True

        for pattern in must_have_patterns:
            if not self.search_in_html([pattern]) and not self.search_in_headers([pattern]):
                return False
        return True

    def check_must_not_have(self, must_not_have_patterns: List[str]) -> bool:
        if not must_not_have_patterns:
            return True

        for pattern in must_not_have_patterns:
            if self.search_in_html([pattern]) or self.search_in_headers([pattern]):
                return False
        return True
