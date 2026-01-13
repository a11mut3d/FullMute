import aiohttp
import random
import asyncio
from aiohttp import ClientTimeout, ClientSession
from fullmute.config.user_agents import USER_AGENTS
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class HttpClient:
    def __init__(self, max_retries=3, timeout=15, proxy_enabled=False, proxy_file=None):
        self.max_retries = max_retries
        self.timeout = timeout
        self.proxy_enabled = proxy_enabled
        self.proxies = []

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

    async def fetch(self, url: str, headers=None):
        retries = 0

        while retries < self.max_retries:
            try:
                timeout = ClientTimeout(total=self.timeout)
                session_headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Connection": "keep-alive"
                }

                if headers:
                    session_headers.update(headers)

                async with ClientSession() as session:
                    proxy = self.get_random_proxy() if self.proxy_enabled else None

                    async with session.get(
                        url,
                        headers=session_headers,
                        timeout=timeout,
                        proxy=proxy,
                        ssl=False
                    ) as response:
                        html = await response.text()
                        headers_dict = dict(response.headers)
                        cookies_dict = {k: v.value for k, v in response.cookies.items()}

                        return html, headers_dict, cookies_dict, response.status

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                retries += 1
                logger.warning(f"Error fetching {url}: {e}. Retry {retries}/{self.max_retries}")
                if retries < self.max_retries:
                    await asyncio.sleep(2 ** retries)
                else:
                    logger.error(f"Failed to fetch {url} after {self.max_retries} retries")
                    return None, {}, {}, 0

        return None, {}, {}, 0
