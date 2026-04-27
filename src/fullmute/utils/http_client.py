import aiohttp
import random
import asyncio
import socket
import ipaddress
import re
import gc
import weakref
import time
from urllib.parse import urlparse, urljoin
from typing import Optional, Dict, Any, List, Tuple, Set
from aiohttp import ClientTimeout, ClientSession, TCPConnector
from fullmute.config.user_agents import USER_AGENTS
from fullmute.utils.logger import setup_logger
from fullmute.utils.cloudflare_bypass import CloudflareBypass

logger = setup_logger()



BLOCKED_HOSTS = {
    'localhost', '127.0.0.1', '::1', '0.0.0.0',
    'internal', 'intranet', 'admin', 'administrator',
    'metadata.google.internal', 'metadata',  
}

BLOCKED_HOST_PATTERNS = [
    r'^.*\.local$',
    r'^.*\.internal$',
    r'^.*\.lan$',
    r'^.*\.private$',
    r'^metadata\..*$',  
    r'^169\.254\..*$',  
    r'^.*\.consul$',
    r'^.*\.kubernetes$',
]



class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0,
                 half_open_max_calls: int = 3):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        
        self.failures: List[float] = []  
        self.state = 'closed'  
        self.last_failure_time: Optional[float] = None
        self.half_open_calls = 0
        self._lock = asyncio.Lock()
        
    async def call(self, func, *args, **kwargs):
        async with self._lock:
            if self.state == 'open':
                
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = 'half-open'
                    self.half_open_calls = 0
                    logger.info("Circuit breaker: entering half-open state")
                else:
                    raise Exception("Circuit breaker is OPEN")
        
        try:
            result = await func(*args, **kwargs)
            async with self._lock:
                if self.state == 'half-open':
                    self.half_open_calls += 1
                    if self.half_open_calls >= self.half_open_max_calls:
                        self.state = 'closed'
                        self.failures.clear()
                        logger.info("Circuit breaker: closed (recovered)")
            return result
        except Exception as e:
            async with self._lock:
                self.failures.append(time.time())
                self.last_failure_time = time.time()
                
                
                cutoff = time.time() - self.recovery_timeout
                self.failures = [t for t in self.failures if t > cutoff]
                
                if len(self.failures) >= self.failure_threshold:
                    self.state = 'open'
                    logger.warning(f"Circuit breaker: OPEN ({len(self.failures)} failures)")
            raise



_global_circuit_breaker: Optional[CircuitBreaker] = None


def get_global_circuit_breaker() -> CircuitBreaker:
    """Get or create global circuit breaker"""
    global _global_circuit_breaker
    if _global_circuit_breaker is None:
        _global_circuit_breaker = CircuitBreaker(
            failure_threshold=10,  
            recovery_timeout=60.0,  
            half_open_max_calls=5  
        )
    return _global_circuit_breaker


def is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        return (
            ip_obj.is_private or 
            ip_obj.is_loopback or 
            ip_obj.is_link_local or 
            ip_obj.is_multicast or
            ip_obj.is_reserved or
            ip_obj.is_unspecified or
            
            (isinstance(ip_obj, ipaddress.IPv4Address) and (
                ip_obj in ipaddress.ip_network('10.0.0.0/8') or
                ip_obj in ipaddress.ip_network('172.16.0.0/12') or
                ip_obj in ipaddress.ip_network('192.168.0.0/16') or
                ip_obj in ipaddress.ip_network('127.0.0.0/8') or
                ip_obj in ipaddress.ip_network('169.254.0.0/16') or
                ip_obj in ipaddress.ip_network('224.0.0.0/4')
            )) or
            
            (isinstance(ip_obj, ipaddress.IPv6Address) and (
                ip_obj in ipaddress.ip_network('fc00::/7') or  
                ip_obj in ipaddress.ip_network('fe80::/10') or  
                ip_obj in ipaddress.ip_network('::1/128') or  
                ip_obj in ipaddress.ip_network('ff00::/8')  
            ))
        )
    except (ValueError, TypeError):
        return False


def is_blocked_hostname(hostname: str) -> bool:
    hostname_lower = hostname.lower()
    
    
    if hostname_lower in BLOCKED_HOSTS:
        return True
    
    
    for pattern in BLOCKED_HOST_PATTERNS:
        if re.match(pattern, hostname_lower, re.IGNORECASE):
            logger.warning(f"Hostname matches blocked pattern: {hostname}")
            return True
    
    
    try:
        
        ip = ipaddress.ip_address(hostname)
        return is_private_ip(str(ip))
    except ValueError:
        pass
    
    return False


async def check_url_safety(url: str, check_redirects: bool = True) -> bool:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            logger.warning(f"No hostname in URL: {url}")
            return False

        
        if parsed.scheme not in ('http', 'https'):
            logger.warning(f"Blocked non-HTTP(S) URL: {url}")
            return False

        
        if is_blocked_hostname(hostname):
            logger.warning(f"Blocked access to dangerous hostname: {hostname}")
            return False

        
        if not parsed.netloc:
            logger.warning(f"Blocked relative URL: {url}")
            return False

        
        try:
            ip = ipaddress.ip_address(hostname)
            if is_private_ip(str(ip)):
                logger.warning(f"Blocked access to private IP: {ip}")
                return False
        except ValueError:
            
            pass

        
        try:
            
            addr_info = socket.getaddrinfo(
                hostname, None, 
                socket.AF_UNSPEC,  
                socket.SOCK_STREAM
            )
            
            if not addr_info:
                logger.warning(f"No DNS records for hostname: {hostname}")
                return False
            
            for info in addr_info:
                ip = info[4][0]
                if is_private_ip(ip):
                    logger.warning(f"Blocked access to private IP: {ip} for hostname: {hostname}")
                    return False
                    
        except socket.gaierror as e:
            logger.warning(f"DNS resolution failed for {hostname}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error during DNS check: {e}")
            return False

        return True
        
    except Exception as e:
        logger.error(f"Error checking URL safety: {e}")
        return False


async def validate_redirect_url(base_url: str, redirect_url: str) -> bool:
    try:
        
        parsed_base = urlparse(base_url)
        parsed_redirect = urlparse(redirect_url)
        
        
        if not parsed_redirect.netloc:
            return True
        
        
        if parsed_redirect.scheme not in ('http', 'https'):
            logger.warning(f"Blocked redirect to non-HTTP(S) URL: {redirect_url}")
            return False
        
        
        return await check_url_safety(redirect_url, check_redirects=False)
        
    except Exception as e:
        logger.error(f"Error validating redirect: {e}")
        return False

class HttpClient:
    
    _session_cache: Dict[str, ClientSession] = {}
    _session_lock = asyncio.Lock()
    _max_cached_sessions = 10

    def __init__(self, max_retries=3, timeout=15, proxy_enabled=False, proxy_file=None,
                 bypass_cloudflare=True, max_redirects=5, max_concurrent=10,
                 enable_session_cache=True):
        self.max_retries = max_retries
        self.timeout = timeout
        self.proxy_enabled = proxy_enabled
        self.proxy_file = proxy_file
        self.proxies: List[str] = []
        self.bypass_cloudflare = bypass_cloudflare
        self.max_redirects = max_redirects
        self.enable_session_cache = enable_session_cache
        self._session: Optional[ClientSession] = None
        self._connector: Optional[TCPConnector] = None
        self._closed = False
        
        
        self._host_failures: Dict[str, int] = {}
        self._host_failure_threshold = 3  
        self._host_lock = asyncio.Lock()

        
        self._connector_config = {
            'limit': max_concurrent * 2,  
            'limit_per_host': min(max_concurrent, 5),  
            'ttl_dns_cache': 300,
            'use_dns_cache': True,
            'enable_cleanup_closed': True,
            'keepalive_timeout': 30.0,
            'force_close': False,
        }

        
        if proxy_enabled and proxy_file:
            self.load_proxies(proxy_file)

        
        self.cf_bypass = CloudflareBypass(max_retries=max_retries, timeout=timeout)

        logger.debug(f"HttpClient initialized: max_retries={max_retries}, timeout={timeout}s, "
                    f"max_concurrent={max_concurrent}, proxy={proxy_enabled}")

    def load_proxies(self, proxy_file: str):
        try:
            with open(proxy_file, 'r', encoding='utf-8') as f:
                self.proxies = [
                    line.strip() for line in f 
                    if line.strip() and not line.startswith('#'):
                        self.proxies.append(line.strip())
                ]
            logger.info(f"Loaded {len(self.proxies)} proxies from {proxy_file}")
        except Exception as e:
            logger.error(f"Failed to load proxies: {e}")
            self.proxies = []

    def get_random_proxy(self) -> Optional[str]:
        if self.proxies:
            return random.choice(self.proxies)
        return None

    async def _get_session(self) -> ClientSession:
        if self._session is None or self._session.closed:
            
            
            
            
            timeout = ClientTimeout(
                total=self.timeout,  
                connect=3,  
                sock_read=7,  
                sock_connect=3  
            )

            self._connector = TCPConnector(**self._connector_config)

            self._session = ClientSession(
                connector=self._connector,
                timeout=timeout,
                auto_decompress=True,
                raise_for_status=False
            )
            logger.debug("Created new HTTP session")

        return self._session

    async def fetch(self, url: str, headers=None) -> Tuple[Optional[str], Dict, Dict, int, str]:
        
        is_safe = await check_url_safety(url)
        if not is_safe:
            logger.error(f"SSRF protection: Blocked access to {url}")
            return None, {}, {}, 403, url

        
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        
        async with self._host_lock:
            if host in self._host_failures and self._host_failures[host] >= self._host_failure_threshold:
                logger.warning(f"Host {host} has {self._host_failures[host]} failures - failing fast")
                return None, {}, {}, 503, url

        
        circuit_breaker = get_global_circuit_breaker()
        if circuit_breaker.state == 'open':
            logger.warning(f"Circuit breaker OPEN - failing fast for {url}")
            return None, {}, {}, 503, url

        retries = 0
        redirect_count = 0
        current_url = url
        last_error = None
        consecutive_failures = 0

        while retries < self.max_retries and not self._closed:
            session = None
            response = None
            start_time = time.time()

            try:
                session = await self._get_session()
                session_headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Connection": "keep-alive"
                }

                if headers:
                    session_headers.update(headers)

                proxy = self.get_random_proxy() if self.proxy_enabled else None

                
                async with session.get(
                    current_url,
                    headers=session_headers,
                    proxy=proxy,
                    ssl=False,
                    allow_redirects=False,
                    max_redirects=0
                ) as response:
                    
                    if response.status in (301, 302, 303, 307, 308):
                        redirect_url = response.headers.get('Location', '')

                        if redirect_url:
                            redirect_count += 1

                            
                            if redirect_count > self.max_redirects:
                                logger.error(f"SSRF protection: Too many redirects ({redirect_count})")
                                return None, {}, {}, 403, url

                            
                            if not redirect_url.startswith(('http://', 'https://')):
                                redirect_url = urljoin(current_url, redirect_url)

                            
                            is_redirect_safe = await validate_redirect_url(current_url, redirect_url)
                            if not is_redirect_safe:
                                logger.error(f"SSRF protection: Blocked unsafe redirect to {redirect_url}")
                                return None, {}, {}, 403, url

                            
                            current_url = redirect_url
                            logger.debug(f"Following redirect to: {current_url}")
                            continue

                    
                    html = await response.text(errors='backslashreplace')
                    headers_dict = dict(response.headers)
                    cookies_dict = {k: v.value for k, v in response.cookies.items()}
                    final_url = current_url

                    
                    consecutive_failures = 0
                    async with self._host_lock:
                        if host in self._host_failures:
                            del self._host_failures[host]

                    
                    if response.status == 403 or self._is_cloudflare_challenge(html):
                        if self.bypass_cloudflare:
                            logger.info(f"Detected Cloudflare protection for {url}, attempting bypass...")
                            return await self.cf_bypass.bypass_cloudflare(url, headers)
                        else:
                            logger.warning(f"Received 403/Cloudflare for {url} but bypass is disabled")

                    return html, headers_dict, cookies_dict, response.status, final_url

            except asyncio.TimeoutError as e:
                last_error = e
                retries += 1
                consecutive_failures += 1
                elapsed = time.time() - start_time

                logger.warning(f"Timeout fetching {url} after {elapsed:.1f}s: {e}. Retry {retries}/{self.max_retries}")

                
                async with self._host_lock:
                    self._host_failures[host] = self._host_failures.get(host, 0) + 1

                
                if consecutive_failures >= 2:
                    logger.warning(f"Multiple consecutive timeouts for {url}, failing fast")
                    break

                
                if retries < self.max_retries:
                    wait_time = min(2 ** (retries - 1), 1.0) + random.uniform(0, 0.2)
                    await asyncio.sleep(wait_time)

            except aiohttp.ClientConnectorError as e:
                
                last_error = e
                retries += 1
                consecutive_failures += 1

                logger.warning(f"Connection error for {url}: {e}. Failing fast")

                
                async with self._host_lock:
                    self._host_failures[host] = self._host_failures.get(host, 0) + 1

                
                break

            except aiohttp.ClientError as e:
                last_error = e
                retries += 1
                consecutive_failures += 1

                logger.warning(f"Client error fetching {url}: {e}. Retry {retries}/{self.max_retries}")

                
                async with self._host_lock:
                    self._host_failures[host] = self._host_failures.get(host, 0) + 1

                
                if "cloudflare" in str(e).lower() and self.bypass_cloudflare:
                    logger.info(f"Detected Cloudflare error for {url}, attempting bypass...")
                    return await self.cf_bypass.bypass_cloudflare(url, headers)

                
                if consecutive_failures >= 2:
                    logger.warning(f"Multiple consecutive errors for {url}, failing fast")
                    break

                
                if retries < self.max_retries:
                    wait_time = min(2 ** (retries - 1), 1.0) + random.uniform(0, 0.2)
                    await asyncio.sleep(wait_time)

            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error fetching {url}: {e}")
                retries += 1
                consecutive_failures += 1

                
                async with self._host_lock:
                    self._host_failures[host] = self._host_failures.get(host, 0) + 1

                
                if consecutive_failures >= 2:
                    logger.warning(f"Unexpected error, failing fast for {url}")
                    break

                if retries < self.max_retries:
                    await asyncio.sleep(min(2 ** (retries - 1), 1.0))
                else:
                    break

        
        logger.error(f"Failed to fetch {url} after {retries} retries. Last error: {last_error}")
        return None, {}, {}, 0, url

    async def close(self):
        """Close HTTP session and connector to release resources"""
        if self._closed:
            return
            
        self._closed = True
        
        try:
            if self._session and not self._session.closed:
                await self._session.close()
                logger.debug("HTTP session closed")
            
            if self._connector and not self._connector.closed:
                await self._connector.close()
                logger.debug("HTTP connector closed")
        except Exception as e:
            logger.debug(f"Error closing HTTP resources: {e}")
        finally:
            self._session = None
            self._connector = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        
    def __del__(self):
        if not self._closed:
            try:
                if self._session and not self._session.closed:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(self.close())
                    else:
                        loop.run_until_complete(self.close())
            except Exception:
                pass

    def _is_cloudflare_challenge(self, html: str) -> bool:
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
