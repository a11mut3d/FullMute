import asyncio
import socket
import ssl
import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from fullmute.utils.logger import setup_logger
from fullmute.utils.cve_checker import CVEChecker
from fullmute.utils.searchsploit import search_sploit_batch
from fullmute.scanner.ssh_creds_checker import test_ssh_credentials

logger = setup_logger()


logging.getLogger('paramiko').setLevel(logging.CRITICAL)
logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)


async def resolve_hostname_to_ip(hostname: str, timeout: float = 5.0) -> Optional[str]:
    import ipaddress
    
    
    try:
        ipaddress.ip_address(hostname)
        logger.debug(f"Host is already an IP: {hostname}")
        return hostname
    except ValueError:
        pass
    
    
    try:
        logger.info(f"Resolving hostname {hostname} to IP...")
        addr_info = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: socket.getaddrinfo(
                hostname,
                None,
                socket.AF_INET,  
                socket.SOCK_STREAM
            )
        )
        
        if addr_info:
            
            ip = addr_info[0][4][0]
            logger.info(f"Resolved {hostname} -> {ip}")
            return ip
        else:
            logger.warning(f"No DNS records found for {hostname}")
            return None
            
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for {hostname}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error resolving hostname {hostname}: {e}")
        return None


def resolve_hostname_sync(hostname: str, timeout: float = 5.0) -> Optional[str]:
    import ipaddress
    
    
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(hostname)
        logger.info(f"Resolved {hostname} -> {ip}")
        return ip
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for {hostname}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error resolving hostname {hostname}: {e}")
        return None



TOP_20_PORTS = [
    21,    
    22,    
    23,    
    25,    
    53,    
    80,    
    110,   
    139,   
    143,   
    443,   
    445,   
    993,   
    995,   
    1433,  
    1521,  
    3306,  
    3389,  
    5432,  
    5900,  
    8080,  
]


PORT_SERVICE_MAP = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    80: 'http',
    110: 'pop3',
    139: 'netbios-ssn',
    143: 'imap',
    443: 'https',
    445: 'smb',
    993: 'imaps',
    995: 'pop3s',
    1433: 'mssql',
    1521: 'oracle',
    3306: 'mysql',
    3389: 'rdp',
    5432: 'postgresql',
    5900: 'vnc',
    8080: 'http-proxy',
}


SERVICE_PATTERNS = {
    'ftp': [
        rb'220 ([^\r\n]+)',  
        rb'FTP server \(Version ([^\)]+)\)',
    ],
    'ssh': [
        rb'SSH-([\d\.]+)',
        rb'SSH-2\.0-([^\s]+)',
    ],
    'smtp': [
        rb'220 ([^\r\n]+)',
        rb'ESMTP ([^\r\n]+)',
    ],
    'http': [
        rb'Server: ([^\r\n]+)',
        rb'X-Powered-By: ([^\r\n]+)',
    ],
    'https': [
        rb'Server: ([^\r\n]+)',
        rb'X-Powered-By: ([^\r\n]+)',
    ],
    'mysql': [
        rb'\x00\x00\x00.*?MySQL ([\d\.]+)',
        rb'MariaDB ([\d\.]+)',
    ],
    'postgresql': [
        rb'PostgreSQL ([\d\.]+)',
    ],
    'mssql': [
        rb'SQL Server ([^\r\n]+)',
    ],
    'oracle': [
        rb'Oracle.*?([0-9\.]+)',
    ],
    'smb': [
        rb'Samba ([\d\.]+)',
        rb'Windows ([^\r\n]+)',
    ],
    'rdp': [
        rb'Cookie: ([^\r\n]+)',
    ],
    'vnc': [
        rb'RFB ([\d\.]+)',
    ],
    'telnet': [
        rb'([^\r\n]+login)',
    ],
    'dns': [
        rb'DNS',
    ],
    'pop3': [
        rb'\+OK ([^\r\n]+)',
    ],
    'imap': [
        rb'\* OK ([^\r\n]+)',
    ],
}


@dataclass
class PortScanResult:
    port: int
    protocol: str  
    state: str  
    service: str
    version: str
    banner: str
    ssl: bool
    product: str
    cves: List[Dict]
    exploits: List[Dict]


class PortScanner:

    def __init__(self, timeout: float = 5.0, max_concurrent: int = 20):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        
    async def scan_port(
        self, 
        host: str, 
        port: int,
        grab_banner: bool = True,
        check_ssl: bool = True
    ) -> PortScanResult:
        async with self._semaphore:
            result = PortScanResult(
                port=port,
                protocol='tcp',
                state='closed',
                service=PORT_SERVICE_MAP.get(port, 'unknown'),
                version='',
                banner='',
                ssl=False,
                product='',
                cves=[],
                exploits=[]
            )
            
            try:
                
                is_open, ssl_detected = await self._check_port(
                    host, port, check_ssl
                )
                
                if not is_open:
                    result.state = 'closed'
                    return result
                
                result.state = 'open'
                result.ssl = ssl_detected
                
                
                if grab_banner:
                    banner, service_info = await self._grab_banner(
                        host, port, ssl_detected, result.service
                    )
                    result.banner = banner
                    result.version = service_info.get('version', '')
                    result.product = service_info.get('product', '')
                    
                    
                    if service_info.get('service'):
                        result.service = service_info['service']
                
            except asyncio.TimeoutError:
                result.state = 'filtered'
                logger.debug(f"Port {host}:{port} filtered (timeout)")
            except ConnectionRefusedError:
                result.state = 'closed'
            except Exception as e:
                result.state = 'filtered'
                logger.debug(f"Port {host}:{port} error: {e}")
            
            return result
    
    async def _check_port(
        self,
        host: str,
        port: int,
        check_ssl: bool = True
    ) -> Tuple[bool, bool]:
        reader = None
        writer = None
        
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            
            
            socket_info = writer.get_extra_info('socket')
            if socket_info is None:
                
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                return False, False
            
            
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

            
            ssl_detected = False
            if check_ssl and port in [443, 993, 995, 465, 587]:
                ssl_detected = await self._detect_ssl(host, port)

            return True, ssl_detected

        except asyncio.TimeoutError:
            return False, False
        except ConnectionRefusedError:
            return False, False
        except OSError as e:
            
            logger.debug(f"OS error checking {host}:{port}: {e}")
            return False, False
        except Exception as e:
            logger.debug(f"Unexpected error checking {host}:{port}: {e}")
            return False, False
        finally:
            
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
    
    async def _detect_ssl(self, host: str, port: int) -> bool:
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, 
                    port,
                    ssl=ssl_context
                ),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    async def _grab_banner(
        self,
        host: str,
        port: int,
        ssl_enabled: bool,
        service: str
    ) -> Tuple[str, Dict[str, str]]:
        banner = ''
        service_info = {'service': service, 'version': '', 'product': ''}
        
        try:
            if ssl_enabled:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host,
                        port,
                        ssl=ssl_context
                    ),
                    timeout=self.timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
            
            
            if service in ['http', 'https', 'http-proxy']:
                
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode()
                writer.write(request)
                
            elif service == 'ftp':
                
                pass
                
            elif service == 'ssh':
                
                pass
                
            elif service == 'smtp':
                request = b"EHLO test\r\n"
                writer.write(request)
                
            elif service == 'pop3':
                request = b"CAPA\r\n"
                writer.write(request)
                
            elif service == 'imap':
                request = b"a CAPABILITY\r\n"
                writer.write(request)
            
            
            try:
                response = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=self.timeout / 2
                )
                
                if response:
                    
                    try:
                        banner = response.decode('utf-8', errors='ignore')
                    except:
                        banner = response.decode('latin-1', errors='ignore')
                    
                    
                    banner = banner.replace('\r\n', '\n').strip()
                    banner = banner[:500]  
                    
                    
                    service_info = self._parse_banner(service, response)
                    
            except asyncio.TimeoutError:
                pass
            
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
                
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"Banner grab error for {host}:{port}: {e}")
        
        return banner, service_info
    
    def _parse_banner(
        self, 
        service: str, 
        banner_bytes: bytes
    ) -> Dict[str, str]:
        result = {'service': service, 'version': '', 'product': ''}
        
        patterns = SERVICE_PATTERNS.get(service, [])
        
        for pattern in patterns:
            try:
                match = re.search(pattern, banner_bytes, re.IGNORECASE)
                if match:
                    version = match.group(1).decode('utf-8', errors='ignore')
                    version = version.strip()
                    
                    
                    version = re.sub(r'[^\d\.a-zA-Z]', ' ', version)
                    version = version.strip()
                    
                    result['version'] = version
                    
                    
                    if service == 'ssh':
                        result['product'] = 'openssh'
                    elif service == 'ftp':
                        if 'vsftpd' in version.lower():
                            result['product'] = 'vsftpd'
                        elif 'proftpd' in version.lower():
                            result['product'] = 'proftpd'
                    elif service == 'mysql':
                        result['product'] = 'mysql'
                    elif service == 'postgresql':
                        result['product'] = 'postgresql'
                    
                    logger.debug(f"Detected {service} version: {version}")
                    break
                    
            except Exception as e:
                logger.debug(f"Pattern match error: {e}")
        
        return result
    
    async def scan_host(
        self,
        host: str,
        ports: List[int] = None,
        grab_banner: bool = True,
        resolve_domain: bool = True
    ) -> List[PortScanResult]:
        
        scan_target = host
        if resolve_domain:
            resolved_ip = await resolve_hostname_to_ip(host)
            if resolved_ip:
                scan_target = resolved_ip
                logger.info(f"Will scan IP {scan_target} for host {host}")
            else:
                logger.warning(f"Could not resolve {host}, using original hostname")

        if ports is None:
            ports = TOP_20_PORTS

        logger.info(f"Scanning {len(ports)} ports on {scan_target} (original: {host})")

        
        tasks = [
            self.scan_port(scan_target, port, grab_banner)
            for port in ports
        ]

        
        results = await asyncio.gather(*tasks, return_exceptions=True)

        
        open_ports = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Port scan error: {result}")
                continue

            if isinstance(result, PortScanResult):
                
                if result.state == 'open' and result.banner and result.banner.strip():
                    open_ports.append(result)
                    logger.debug(f"Port {result.port}/{result.service} is OPEN with banner")
                elif result.state == 'open' and not result.banner:
                    logger.debug(f"Port {result.port} is OPEN but no banner (filtered)")
                else:
                    logger.debug(f"Port {result.port} is {result.state} (closed/filtered)")

        logger.info(f"Found {len(open_ports)} open ports with banners on {scan_target}")
        return open_ports
    
    async def scan_with_cves(
        self,
        host: str,
        ports: List[int] = None,
        nvd_api_key: str = None,
        search_exploits: bool = False,
        test_default_credentials: bool = False,
        resolve_domain: bool = True
    ) -> List[PortScanResult]:
        
        scan_target = host
        if resolve_domain:
            resolved_ip = await resolve_hostname_to_ip(host)
            if resolved_ip:
                scan_target = resolved_ip
                logger.info(f"Will scan IP {scan_target} for host {host}")
            else:
                logger.warning(f"Could not resolve {host}, using original hostname")

        
        results = await self.scan_host(scan_target, ports, grab_banner=True, resolve_domain=False)

        
        services_to_check = []
        for result in results:
            if result.product and result.version:
                services_to_check.append((result.product, result.version))
            elif result.service and result.version:
                services_to_check.append((result.service, result.version))

        if not services_to_check:
            
            if test_default_credentials:
                ssh_result = next((r for r in results if r.port == 22 and r.service == 'ssh'), None)
                if ssh_result:
                    logger.info(f"Testing SSH credentials on port 22...")
                    try:
                        ssh_creds = await test_ssh_credentials(
                            scan_target,
                            port=22,
                            test_default_credentials=True,
                            timeout=10,
                            max_attempts=5
                        )
                        if ssh_creds:
                            logger.warning(f"Found {len(ssh_creds)} SSH credential(s)!")
                            
                            ssh_result.default_credentials = ssh_creds
                    except Exception as e:
                        logger.error(f"SSH credential test failed for {scan_target}: {type(e).__name__}: {e}")
                        

            
            return results

        
        cve_checker = CVEChecker(
            nvd_api_key=nvd_api_key,
            rate_limit=True
        )

        cve_results = await cve_checker.check_cves_batch(services_to_check)

        
        for result in results:
            service_key = f"{result.product} ({result.version})"
            if not service_key.startswith(' ('):
                result.cves = cve_results.get(service_key, [])

            
            if search_exploits and result.cves:
                cve_ids = [cve.get('id') for cve in result.cves if cve.get('id')]
                if cve_ids:
                    exploit_results = search_sploit_batch(cve_ids)
                    result.exploits = [
                        {'cve_id': cve_id, 'exploits': exps}
                        for cve_id, exps in exploit_results.items()
                        if exps
                    ]

            
            if test_default_credentials and result.port == 22 and result.service == 'ssh':
                logger.info(f"Testing SSH credentials on port 22...")
                try:
                    ssh_creds = await test_ssh_credentials(
                        scan_target,
                        port=22,
                        test_default_credentials=True,
                        timeout=10,
                        max_attempts=5
                    )
                    if ssh_creds:
                        logger.warning(f"Found {len(ssh_creds)} SSH credential(s)!")
                        result.default_credentials = ssh_creds
                except Exception as e:
                    logger.error(f"SSH credential test failed for {scan_target}: {type(e).__name__}: {e}")
                    

        return results


async def scan_ports(
    host: str,
    ports: List[int] = None,
    timeout: float = 5.0,
    grab_banner: bool = True,
    resolve_domain: bool = True
) -> List[Dict]:
    scanner = PortScanner(timeout=timeout)
    results = await scanner.scan_host(host, ports, grab_banner, resolve_domain)
    return [asdict(r) for r in results]


async def scan_ports_with_cves(
    host: str,
    ports: List[int] = None,
    timeout: float = 5.0,
    nvd_api_key: str = None,
    search_exploits: bool = False,
    resolve_domain: bool = True
) -> List[Dict]:

    scanner = PortScanner(timeout=timeout)
    results = await scanner.scan_with_cves(
        host,
        ports,
        nvd_api_key=nvd_api_key,
        search_exploits=search_exploits
    )
    return [asdict(r) for r in results]
