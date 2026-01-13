import random
import aiohttp
from typing import List
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class ProxyManager:
    def __init__(self, proxy_file: str = None):
        self.proxies: List[str] = []
        if proxy_file:
            self.load_proxies(proxy_file)

    def load_proxies(self, file_path: str):
        try:
            with open(file_path, 'r') as f:
                self.proxies = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(self.proxies)} proxies from {file_path}")
        except Exception as e:
            logger.error(f"Failed to load proxies from {file_path}: {e}")

    def get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    async def test_proxy(self, proxy: str):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://httpbin.org/ip",
                    proxy=proxy,
                    timeout=10,
                    ssl=False
                ) as response:
                    if response.status == 200:
                        logger.debug(f"Proxy {proxy} is working")
                        return True
        except Exception as e:
            logger.debug(f"Proxy {proxy} failed: {e}")
        return False

    async def validate_proxies(self):
        valid_proxies = []
        for proxy in self.proxies:
            if await self.test_proxy(proxy):
                valid_proxies.append(proxy)

        self.proxies = valid_proxies
        logger.info(f"Validated proxies: {len(self.proxies)} working")
