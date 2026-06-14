import asyncio
import aiohttp
import random
from typing import Tuple, Dict, Any, Optional
from urllib.parse import urlparse
from fullmute.config.user_agents import USER_AGENTS
from fullmute.utils.logger import setup_logger

logger = setup_logger()

try:
    from playwright.async_api import async_playwright, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not installed. Cloudflare bypass will fall back to standard requests.")


class CloudflareBypass:
    def __init__(self, max_retries=3, timeout=30, use_playwright=True, headless=True, proxy=None):
        self.max_retries = max_retries
        self.timeout = timeout
        self.use_playwright = use_playwright and PLAYWRIGHT_AVAILABLE
        self.headless = headless
        self.proxy = proxy
        self._cookies_cache = {}   # domain -> {cookie_name: cookie_value}
        self._last_used = {}       # domain -> timestamp

    async def bypass_cloudflare(self, url: str, headers: Dict[str, str] = None) -> Tuple[str, Dict[str, str], Dict[str, str], int, str]:
        """
        Main method to bypass Cloudflare protection.
        Returns: (html, headers_dict, cookies_dict, status_code, final_url)
        """
        if not self.use_playwright:
            return await self._fallback_fetch(url, headers)

        domain = urlparse(url).netloc
        cookies = self._get_cached_cookies(domain)

        if cookies is not None:
            logger.debug(f"Using cached Cloudflare cookies for {domain}")
            result = await self._fetch_with_cookies(url, headers, cookies)
            if result and not self._is_cloudflare_challenge(result[0]):
                return result
            logger.debug(f"Cached cookies expired or invalid for {domain}, re-solving challenge")

        logger.info(f"Solving Cloudflare challenge for {url} using Playwright")
        try:
            cookies, final_url = await self._solve_challenge(url)
            if cookies:
                self._cache_cookies(domain, cookies)
                result = await self._fetch_with_cookies(url, headers, cookies)
                if result:
                    return result
        except Exception as e:
            logger.error(f"Playwright Cloudflare bypass failed: {e}")

        return await self._fallback_fetch(url, headers)

    async def _solve_challenge(self, url: str) -> Tuple[Dict[str, str], str]:
        """
        Launches headless browser, navigates to URL, waits for Cloudflare challenge to complete,
        and returns cookies and final URL.
        """
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError("Playwright is not installed")

        async with async_playwright() as p:
            launch_options = {
                "headless": self.headless,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                ]
            }
            if self.proxy:
                launch_options["proxy"] = {"server": self.proxy}

            browser = await p.chromium.launch(**launch_options)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent=random.choice(USER_AGENTS),
                ignore_https_errors=True
            )
            page = await context.new_page()

            try:
                await page.goto(url, wait_until="networkidle", timeout=self.timeout * 1000)
                await self._wait_for_challenge_resolution(page)
                playwright_cookies = await context.cookies()
                cookies_dict = {c["name"]: c["value"] for c in playwright_cookies}
                final_url = page.url
                logger.info(f"Cloudflare challenge solved for {url}, got {len(cookies_dict)} cookies")
                return cookies_dict, final_url
            finally:
                await browser.close()

    async def _wait_for_challenge_resolution(self, page: "Page", max_wait: int = 30) -> None:
        """Waits until Cloudflare challenge page disappears."""
        start = asyncio.get_event_loop().time()
        while (asyncio.get_event_loop().time() - start) < max_wait:
            html = await page.content()
            if not self._is_cloudflare_challenge(html):
                return
            await asyncio.sleep(1)
        logger.warning(f"Cloudflare challenge did not resolve within {max_wait} seconds, proceeding anyway")

    async def _fetch_with_cookies(self, url: str, headers: Optional[Dict[str, str]], cookies: Dict[str, str]) -> Optional[Tuple[str, Dict[str, str], Dict[str, str], int, str]]:
        """Perform aiohttp GET request with given cookies."""
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

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=session_headers, cookies=cookies, ssl=False, allow_redirects=True) as resp:
                    html = await resp.text(errors='backslashreplace')
                    headers_dict = dict(resp.headers)
                    cookies_dict = {k: v.value for k, v in resp.cookies.items()}
                    cookies_dict.update(cookies)
                    return html, headers_dict, cookies_dict, resp.status, str(resp.url)
        except Exception as e:
            logger.debug(f"Fetch with cookies failed: {e}")
            return None

    async def _fallback_fetch(self, url: str, headers: Optional[Dict[str, str]]) -> Tuple[str, Dict[str, str], Dict[str, str], int, str]:
        """Original aiohttp-based fetch without JS execution."""
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
                    async with session.get(url, headers=session_headers, ssl=False, allow_redirects=True) as response:
                        html = await response.text(errors='backslashreplace')
                        headers_dict = dict(response.headers)
                        cookies_dict = {k: v.value for k, v in response.cookies.items()}
                        return html, headers_dict, cookies_dict, response.status, str(response.url)
                except Exception as e:
                    if attempt == self.max_retries - 1:
                        raise e
                    await asyncio.sleep(2 ** attempt)
        return "", {}, {}, 403, url

    def _get_cached_cookies(self, domain: str) -> Optional[Dict[str, str]]:
        return self._cookies_cache.get(domain)

    def _cache_cookies(self, domain: str, cookies: Dict[str, str]) -> None:
        self._cookies_cache[domain] = cookies
        self._last_used[domain] = asyncio.get_event_loop().time()

    def _is_cloudflare_challenge(self, html: str) -> bool:
        indicators = [
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
        return any(indicator.lower() in html_lower for indicator in indicators)
