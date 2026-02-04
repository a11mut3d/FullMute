import asyncio
import aiohttp
import random
from typing import Tuple, Dict, Any
from fullmute.config.user_agents import USER_AGENTS
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class CloudflareBypass:
    def __init__(self, max_retries=3, timeout=30):
        self.max_retries = max_retries
        self.timeout = timeout

    async def bypass_cloudflare(self, url: str, headers: Dict[str, str] = None) -> Tuple[str, Dict[str, str], Dict[str, str], int]:
        """
        Попытка обойти защиту Cloudflare
        """
        # Попробуем несколько подходов для обхода Cloudflare
        approaches = [
            self._fetch_with_standard_request,
            self._fetch_with_retry_headers,
            self._fetch_with_session_persistence
        ]

        for approach in approaches:
            try:
                result = await approach(url, headers)
                html, headers_dict, cookies_dict, status = result
                
                if html and status != 403 and not self._is_cloudflare_challenge(html):
                    return html, headers_dict, cookies_dict, status
            except Exception as e:
                logger.debug(f"Approach failed: {e}")
                continue
        
        # Если все подходы не сработали, возвращаем результат последней попытки
        return "", {}, {}, 403

    async def _fetch_with_standard_request(self, url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], Dict[str, str], int]:
        """Стандартный запрос с повторными попытками"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        session_headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        if headers:
            session_headers.update(headers)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for attempt in range(self.max_retries):
                try:
                    async with session.get(url, headers=session_headers, ssl=False) as response:
                        html = await response.text()
                        headers_dict = dict(response.headers)
                        cookies_dict = {k: v.value for k, v in response.cookies.items()}
                        
                        return html, headers_dict, cookies_dict, response.status
                except Exception as e:
                    if attempt == self.max_retries - 1:
                        raise e
                    await asyncio.sleep(2 ** attempt)  # Экспоненциальная задержка
    
    async def _fetch_with_retry_headers(self, url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], Dict[str, str], int]:
        """Запрос с изменением заголовков при повторных попытках"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Cache-Control": "max-age=0"
        }
        
        if headers:
            base_headers.update(headers)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for attempt in range(self.max_retries):
                try:
                    # Изменяем User-Agent при каждой попытке
                    current_headers = base_headers.copy()
                    current_headers["User-Agent"] = random.choice(USER_AGENTS)
                    
                    async with session.get(url, headers=current_headers, ssl=False) as response:
                        html = await response.text()
                        headers_dict = dict(response.headers)
                        cookies_dict = {k: v.value for k, v in response.cookies.items()}
                        
                        return html, headers_dict, cookies_dict, response.status
                except Exception as e:
                    if attempt == self.max_retries - 1:
                        raise e
                    await asyncio.sleep(2 ** attempt)

    async def _fetch_with_session_persistence(self, url: str, headers: Dict[str, str]) -> Tuple[str, Dict[str, str], Dict[str, str], int]:
        """Запрос с сохранением сессии и обработкой редиректов"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        session_headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        
        if headers:
            session_headers.update(headers)

        # Создаем постоянную сессию с обработчиком редиректов
        connector = aiohttp.TCPConnector(limit=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for attempt in range(self.max_retries):
                try:
                    # Сначала получаем страницу без follow redirects
                    async with session.get(url, headers=session_headers, allow_redirects=True, ssl=False) as response:
                        html = await response.text()
                        headers_dict = dict(response.headers)
                        cookies_dict = {k: v.value for k, v in response.cookies.items()}
                        
                        return html, headers_dict, cookies_dict, response.status
                except Exception as e:
                    if attempt == self.max_retries - 1:
                        raise e
                    await asyncio.sleep(2 ** attempt)

    def _is_cloudflare_challenge(self, html: str) -> bool:
        """Проверяет, является ли ответ Cloudflare challenge"""
        cloudflare_indicators = [
            "Checking your browser before accessing",
            "You are being redirected",
            "Please turn JavaScript on and reload the page",
            "enable JavaScript in your browser",
            "Checking your browser",
            "Just a moment",
            "Cloudflare",
            "Ray ID:"
        ]
        
        html_lower = html.lower()
        return any(indicator.lower() in html_lower for indicator in cloudflare_indicators)