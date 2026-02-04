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

        tasks = []
        for file_type, config in self.signatures.items():
            if not isinstance(config, dict):
                continue

            paths = config.get("paths", [])

            for path in paths:
                task = self._check_file(session, base_url, file_type, path, config.get("verification", {}))
                tasks.append(task)

        file_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in file_results:
            if isinstance(result, dict) and result.get("found"):
                results.append(result)

        return results

    async def _check_file(self, session: aiohttp.ClientSession, base_url: str,
                         file_type: str, path: str, verification: Dict[str, Any]) -> Dict[str, Any]:
        file_url = f"{base_url.rstrip('/')}{path}"

        try:
            async with session.get(file_url, timeout=self.timeout, ssl=False) as response:
                if response.status == 200:
                    content = await response.text()

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

        except asyncio.TimeoutError:
            logger.debug(f"Timeout checking {file_url}")
        except Exception as e:
            logger.debug(f"Error checking {file_url}: {e}")

        return {"found": False}

    def _verify_content(self, content: str, verification: Dict[str, Any]) -> bool:
        method = verification.get("method", "content")
        patterns = verification.get("patterns", [])
        must_have = verification.get("must_have", [])
        must_not_have = verification.get("must_not_have", [])

        # Проверяем must_not_have условия
        if must_not_have:
            for pattern in must_not_have:
                if re.search(pattern, content, re.IGNORECASE):
                    return False

        # Проверяем must_have условия
        if must_have:
            found_required = False
            for pattern in must_have:
                if re.search(pattern, content, re.IGNORECASE):
                    found_required = True
                    break
            if not found_required:
                return False

        if method == "content" and patterns:
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True

        elif method == "extension":
            return True

        elif method == "redirect":
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True

        elif method == "directory_listing":
            # Для проверки списка каталогов проверяем наличие нескольких ключевых элементов
            found_elements = 0
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_elements += 1
            # Требуем хотя бы 2 совпадения для подтверждения
            return found_elements >= 2

        elif method == "config_content":
            # Для конфигурационных файлов требуем больше уверенности
            found_elements = 0
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_elements += 1
            return found_elements >= 1

        elif method == "login_form":
            # Для форм входа проверяем наличие нескольких признаков
            found_elements = 0
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_elements += 1
            return found_elements >= 2

        elif method == "sql_content":
            # Для SQL-дампов проверяем наличие ключевых команд
            found_elements = 0
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_elements += 1
            return found_elements >= 1

        return False
