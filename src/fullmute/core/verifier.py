import aiohttp
import re
import asyncio
from typing import List, Dict, Any
from urllib.parse import urljoin
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class SensitiveFileVerifier:
    def __init__(
        self,
        signatures: Dict[str, Any],
        timeout: int = 10,
        cms_signatures: Dict[str, Any] = None,
        max_concurrent: int = 8,
    ):
        self.signatures = signatures
        self.timeout = timeout
        self.cms_signatures = cms_signatures or {}
        self.max_concurrent = max(1, int(max_concurrent))

    async def verify(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        detected_technologies=None,
    ) -> List[Dict[str, Any]]:
        if session is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as new_session:
                return await self._verify_with_session(
                    new_session,
                    base_url,
                    detected_technologies,
                )
        else:
            return await self._verify_with_session(
                session,
                base_url,
                detected_technologies,
            )

    async def _verify_with_session(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        detected_technologies,
    ) -> List[Dict[str, Any]]:
        results = await self._verify_general_files(session, base_url)
        cms_names = self._detected_cms_names(detected_technologies)
        if cms_names:
            results.extend(
                await self._verify_cms_paths(session, base_url, cms_names)
            )
        return results

    async def _verify_general_files(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
    ) -> List[Dict[str, Any]]:
        tasks = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        for file_type, config in self.signatures.items():
            if not isinstance(config, dict):
                continue
            for path in config.get("paths", []):
                tasks.append(
                    self._check_file_bounded(
                        semaphore,
                        session,
                        base_url,
                        file_type,
                        path,
                        config.get("verification", {}),
                    )
                )

        try:
            file_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.timeout * 2,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Timeout while verifying sensitive files for %s",
                base_url,
            )
            return []
        return [
            result for result in file_results
            if isinstance(result, dict) and result.get("found")
        ]

    async def _check_file_bounded(
        self,
        semaphore: asyncio.Semaphore,
        session: aiohttp.ClientSession,
        base_url: str,
        file_type: str,
        path: str,
        verification: Dict[str, Any],
    ) -> Dict[str, Any]:
        async with semaphore:
            return await self._check_file(
                session,
                base_url,
                file_type,
                path,
                verification,
            )

    @staticmethod
    def _detected_cms_names(detected_technologies) -> List[str]:
        if not isinstance(detected_technologies, dict):
            return []
        aliases = {
            "wordpress": "WordPress",
            "woocommerce": "WordPress",
            "joomla": "Joomla",
            "joomla!": "Joomla",
            "bitrix": "Bitrix",
            "1c-bitrix": "Bitrix",
            "shopify": "Shopify",
        }
        detected = set()
        for technology_list in detected_technologies.values():
            if not isinstance(technology_list, list):
                continue
            for technology in technology_list:
                if not isinstance(technology, str):
                    continue
                name = technology.split(" (", 1)[0].strip().casefold()
                if name in aliases:
                    detected.add(aliases[name])
        return sorted(detected)

    async def _verify_cms_paths(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        cms_names: List[str],
    ) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = []
        for cms_name in cms_names:
            paths = self.cms_signatures.get(cms_name, [])
            if not isinstance(paths, list):
                continue
            for path in dict.fromkeys(paths):
                if isinstance(path, str) and path.startswith("/"):
                    tasks.append(
                        self._check_cms_path_bounded(
                            semaphore,
                            session,
                            base_url,
                            cms_name,
                            path,
                        )
                    )

        if not tasks:
            return []
        try:
            file_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.timeout * 2,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Timeout while checking CMS endpoints for %s",
                base_url,
            )
            return []
        return [
            result for result in file_results
            if isinstance(result, dict) and result.get("found")
        ]

    async def _check_cms_path_bounded(
        self,
        semaphore: asyncio.Semaphore,
        session: aiohttp.ClientSession,
        base_url: str,
        cms_name: str,
        path: str,
    ) -> Dict[str, Any]:
        async with semaphore:
            file_url = urljoin(base_url, path)
            try:
                async def check_response():
                    async with session.get(
                        file_url,
                        ssl=False,
                        allow_redirects=False,
                    ) as response:
                        status = response.status
                        body = await response.content.read(1024)
                        if body and not response.content.at_eof():
                            response.close()
                        if not (
                            200 <= status < 400
                            or status in {401, 403}
                        ):
                            return {"found": False}
                        return {
                            "found": True,
                            "file_type": f"{cms_name.lower()}_endpoint",
                            "url": file_url,
                            "verification_result": (
                                "restricted_endpoint"
                                if status in {401, 403}
                                else "reachable_endpoint"
                            ),
                            "status_code": status,
                            "content_sample": "",
                            "risk": "informational",
                        }
                return await asyncio.wait_for(check_response(), self.timeout)
            except asyncio.TimeoutError:
                logger.debug("Timeout checking CMS endpoint %s", file_url)
            except Exception as exc:
                logger.debug("Error checking CMS endpoint %s: %s", file_url, exc)
            return {"found": False}

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
