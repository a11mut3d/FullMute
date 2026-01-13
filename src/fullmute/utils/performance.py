import asyncio
import aiohttp
import time
from typing import List, Tuple
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class PerformanceOptimizer:
    def __init__(self, max_concurrent_requests=10, request_timeout=10):
        self.max_concurrent_requests = max_concurrent_requests
        self.request_timeout = request_timeout

    async def fetch(self, session: aiohttp.ClientSession, url: str) -> Tuple[str, int]:
        try:
            async with session.get(url, timeout=self.request_timeout) as response:
                return await response.text(), response.status
        except asyncio.TimeoutError:
            logger.warning(f"Timeout while fetching {url}")
            return None, None
        except Exception as e:
            logger.error(f"Error while fetching {url}: {e}")
            return None, None

    async def fetch_all(self, urls: List[str]) -> List[Tuple[str, int]]:
        semaphore = asyncio.Semaphore(self.max_concurrent_requests)

        async def fetch_with_semaphore(session, url):
            async with semaphore:
                return await self.fetch(session, url)

        async with aiohttp.ClientSession() as session:
            tasks = [fetch_with_semaphore(session, url) for url in urls]
            results = await asyncio.gather(*tasks)
            return results

    def run_batch_scan(self, urls: List[str]):
        logger.info(f"Starting batch scan with {len(urls)} domains...")
        start_time = time.time()
        results = asyncio.run(self.fetch_all(urls))
        end_time = time.time()
        logger.info(f"Batch scan completed in {end_time - start_time:.2f} seconds.")
        return results
