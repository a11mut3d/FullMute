import logging

import aiohttp
import random
import asyncio
from aiohttp import ClientTimeout, ClientSession, TCPConnector
from fullmute.config.user_agents import USER_AGENTS
from fullmute.utils.cloudflare_bypass import CloudflareBypass

logger = logging.getLogger('fullmute')

class HttpClient:
    def __init__(self, max_retries=3, timeout=15, proxy_enabled=False, proxy_file=None, bypass_cloudflare=True):
        self.max_retries = max_retries
        self.timeout = timeout
        self.proxy_enabled = proxy_enabled
        self.proxies = []
        self.bypass_cloudflare = bypass_cloudflare
        self.cf_bypass = CloudflareBypass(max_retries=max_retries, timeout=timeout)

        if proxy_enabled and proxy_file:
            self.load_proxies(proxy_file)

    def load_proxies(self, proxy_file: str):
        try:
            with open(proxy_file, 'r') as f:
                self.proxies = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(self.proxies)} proxies")
        except Exception as e:
            logger.error(f"Failed to load proxies: {e}")

    def get_random_proxy(self):
        if self.proxies:
            return random.choice(self.proxies)
        return None

    def __init__(self, max_retries=3, timeout=15, proxy_enabled=False, proxy_file=None, bypass_cloudflare=True, max_redirects=5):
        self.max_retries = max_retries
        self.timeout = timeout
        self.proxy_enabled = proxy_enabled
        self.proxies = []
        self.bypass_cloudflare = bypass_cloudflare
        self.max_redirects = max_redirects  # Максимальное количество редиректов
        self.cf_bypass = CloudflareBypass(max_retries=max_retries, timeout=timeout)

        # Создаем общий TCP connector с разумными ограничениями
        self.connector = aiohttp.TCPConnector(
            limit=100,  # Общее количество соединений
            limit_per_host=10,  # Количество соединений на один хост
            ttl_dns_cache=300,
            use_dns_cache=True,
            enable_cleanup_closed=True,
            keepalive_timeout=15.0,
            force_close=False
        )

        # Создаем общую сессию
        self.session = None

        if proxy_enabled and proxy_file:
            self.load_proxies(proxy_file)

    async def _get_session(self):
        """Создаем или возвращаем общую сессию"""
        if self.session is None:
            timeout = ClientTimeout(total=self.timeout)
            self.session = ClientSession(
                connector=self.connector,
                timeout=timeout
            )
        return self.session

    async def fetch(self, url: str, headers=None):
        retries = 0

        while retries < self.max_retries:
            try:
                session_headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Connection": "keep-alive"
                }

                if headers:
                    session_headers.update(headers)

                session = await self._get_session()
                proxy = self.get_random_proxy() if self.proxy_enabled else None

                async with session.get(
                    url,
                    headers=session_headers,
                    proxy=proxy,
                    ssl=False,
                    allow_redirects=True,
                    max_redirects=self.max_redirects  # Используем настроенный лимит редиректов
                ) as response:
                    html = await response.text()
                    headers_dict = dict(response.headers)
                    cookies_dict = {k: v.value for k, v in response.cookies.items()}

                    # Получаем финальный URL после редиректов
                    final_url = str(response.url)

                    # Проверяем, является ли ответ Cloudflare защитой
                    if response.status == 403 or self._is_cloudflare_challenge(html):
                        if self.bypass_cloudflare:
                            logger.info(f"Detected Cloudflare protection for {url}, attempting bypass...")
                            html, headers_dict, cookies_dict, status = await self.cf_bypass.bypass_cloudflare(url, headers)
                            return html, headers_dict, cookies_dict, status, url
                        else:
                            logger.warning(f"Received 403/Cloudflare for {url} but bypass is disabled")

                    return html, headers_dict, cookies_dict, response.status, final_url

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                retries += 1
                logger.warning(f"Error fetching {url}: {e}. Retry {retries}/{self.max_retries}")

                # Если это Cloudflare ошибка, пробуем обход
                if "cloudflare" in str(e).lower() and self.bypass_cloudflare:
                    logger.info(f"Detected Cloudflare error for {url}, attempting bypass...")
                    html, headers_dict, cookies_dict, status = self.cf_bypass.bypass_cloudflare(url, headers)
                    return html, headers_dict, cookies_dict, status, url

                if retries < self.max_retries:
                    await asyncio.sleep(2 ** retries)
                else:
                    logger.error(f"Failed to fetch {url} after {self.max_retries} retries")
                    return None, {}, {}, 0, url

        return None, {}, {}, 0, url

    async def close(self):
        """Закрываем сессию при завершении"""
        if self.session:
            await self.session.close()

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
