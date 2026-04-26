import aiohttp
import re
import asyncio
from typing import List, Dict, Any
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class SensitiveFileVerifier:
    def __init__(self, signatures: Dict[str, Any], timeout: int = 10):
        self.signatures = signatures
        self.timeout = timeout

    async def verify(self, session: aiohttp.ClientSession, base_url: str) -> List[Dict[str, Any]]:
        results = []

        if not self.signatures:
            return results

        if session is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as new_session:
                tasks = []
                for file_type, config in self.signatures.items():
                    if not isinstance(config, dict):
                        continue

                    paths = config.get("paths", [])

                    for path in paths:
                        task = self._check_file(new_session, base_url, file_type, path, config.get("verification", {}))
                        tasks.append(task)
                try:
                    file_results = await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=self.timeout * 2
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout while verifying sensitive files for {base_url}")
                    file_results = []

                for result in file_results:
                    if isinstance(result, dict) and result.get("found"):
                        results.append(result)

                return results
        else:
            tasks = []
            for file_type, config in self.signatures.items():
                if not isinstance(config, dict):
                    continue

                paths = config.get("paths", [])

                for path in paths:
                    task = self._check_file(session, base_url, file_type, path, config.get("verification", {}))
                    tasks.append(task)

            try:
                file_results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.timeout * 2
                )
            except asyncio.TimeoutError:
                logger.warning(f"Timeout while verifying sensitive files for {base_url}")
                file_results = []

            for result in file_results:
                if isinstance(result, dict) and result.get("found"):
                    results.append(result)

            return results

    async def _check_file(self, session: aiohttp.ClientSession, base_url: str,
                         file_type: str, path: str, verification: Dict[str, Any]) -> Dict[str, Any]:
        file_url = f"{base_url.rstrip('/')}{path}"

        try:
            content_result = await asyncio.wait_for(
                self._fetch_and_verify_file(session, file_url, file_type, verification),
                timeout=self.timeout
            )
            return content_result
        except asyncio.TimeoutError:
            logger.debug(f"Timeout checking {file_url}")
        except Exception as e:
            logger.debug(f"Error checking {file_url}: {e}")

        return {"found": False}

    async def _fetch_and_verify_file(self, session: aiohttp.ClientSession, file_url: str,
                                   file_type: str, verification: Dict[str, Any]) -> Dict[str, Any]:

        async with session.get(file_url, ssl=False, allow_redirects=True) as response:
            if response.status == 200:
                content = await response.text(errors='backslashreplace')

                is_verified = self._verify_content(content, verification)

                if is_verified:
                    logger.info(f"Found sensitive file: {file_url}")
                    return {
                        "found": True,
                        "file_type": file_type,
                        "url": file_url,
                        "verification_result": "verified",
                        "content_sample": content[:500],
                        "status_code": response.status
                    }

        return {"found": False}

    def _verify_content(self, content: str, verification: Dict[str, Any]) -> bool:
        method = verification.get("method", "content")
        patterns = verification.get("patterns", [])
        must_have = verification.get("must_have", [])
        must_not_have = verification.get("must_not_have", [])

        if must_not_have:
            for pattern in must_not_have:
                if re.search(pattern, content, re.IGNORECASE):
                    return False

        if must_have:
            for pattern in must_have:
                if not re.search(pattern, content, re.IGNORECASE):
                    return False

        if method == "content":
            if not patterns:
                return False
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    return True
            return False

        elif method == "extension":
            if not patterns:
                return False
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            return False

        elif method == "redirect":
            if not patterns:
                return False
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            return False

        elif method == "directory_listing":
            if not patterns:
                return False
            found_elements = 0
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_elements += 1
            return found_elements >= 4

        elif method == "config_content":
            if not patterns:
                return False
            found_elements = 0
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_elements += 1
            return found_elements >= 2

        elif method == "login_form":
            if not patterns:
                return False
            found_elements = 0
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_elements += 1
            return found_elements >= 3

        elif method == "sql_content":
            if not patterns:
                return False
            found_elements = 0
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_elements += 1
            return found_elements >= 2

        return False
