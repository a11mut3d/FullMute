import subprocess
import socket
import ipaddress
import re
from typing import Tuple, Optional
from fullmute.utils.logger import setup_logger

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
]


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


def extract_host_and_port(target: str) -> Tuple[str, Optional[int]]:
    
    target = target.strip()
    if target.startswith('http://'):
        target = target[7:]
    elif target.startswith('https://'):
        target = target[8:]
    
    
    target = target.split('/')[0].split('?')[0].split('#')[0]
    
    
    if ':' in target:
        
        if target.startswith('['):
            
            parts = target.rsplit(']:', 1)
            if len(parts) == 2:
                host = parts[0][1:]  
                port = int(parts[1])
            else:
                host = target[1:-1]  
                port = None
        else:
            
            parts = target.rsplit(':', 1)
            if len(parts) == 2 and parts[1].isdigit():
                host = parts[0]
                port = int(parts[1])
            else:
                host = target
                port = None
    else:
        host = target
        port = None
    
    return host, port


def validate_domain_format(domain: str) -> bool:
    
    domain_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
        r'\.[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(domain))


def validate_ip_format(ip: str) -> bool:
    """Validate IPv4 format"""
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if not ip_pattern.match(ip):
        return False
    
    
    try:
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    except ValueError:
        return False


def ping_host(host: str, timeout: int = 3, count: int = 2) -> Tuple[bool, str]:
    
    if not host or len(host) > 253:
        return False, "Invalid host: too long"
    
    
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', 
                       '<', '>', '\\', '\n', '\r', '\x00']
    for char in dangerous_chars:
        if char in host:
            logger.warning(f"Blocked ping attempt with dangerous characters: {repr(host)}")
            return False, "Invalid host: contains forbidden characters"
    
    
    
    try:
        import platform
        system = platform.system().lower()
        
        if system == 'windows':
            
            cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), host]
        else:
            
            cmd = ['ping', '-c', str(count), '-W', str(timeout), host]
        
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * count + 5,  
            shell=False  
        )
        
        if result.returncode == 0:
            return True, ""
        else:
            
            stderr = result.stderr.lower()
            if 'unknown host' in stderr or 'name resolution failure' in stderr:
                return False, "DNS resolution failed"
            elif 'unreachable' in stderr:
                return False, "Host unreachable"
            elif 'timed out' in stderr or 'request timed out' in stderr:
                return False, "Ping timeout"
            else:
                return False, "Host did not respond to ping"
                
    except subprocess.TimeoutExpired:
        logger.warning(f"Ping timeout for host: {host}")
        return False, "Ping timeout"
    except FileNotFoundError:
        logger.warning("Ping command not found")
        return False, "Ping command not available"
    except Exception as e:
        logger.error(f"Ping error for {host}: {e}")
        return False, f"Ping error: {str(e)}"


def dns_resolve(host: str, timeout: float = 3.0) -> Tuple[bool, str]:
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(host)
        return True, ""
    except socket.gaierror as e:
        if e.errno == socket.EAI_NONAME or "Name or service not known" in str(e):
            return False, "DNS resolution failed"
        return False, f"DNS error: {str(e)}"
    except socket.timeout:
        return False, "DNS timeout"
    except Exception as e:
        logger.error(f"DNS resolution error for {host}: {e}")
        return False, f"DNS error: {str(e)}"


def validate_target(target: str, require_ping: bool = True) -> Tuple[bool, str, str]:
    
    if not target or not isinstance(target, str):
        return False, "", "Invalid target: empty or not a string"
    
    
    dangerous_patterns = [
    '${', '#',
    '<%', '%>',
    '__',
]
    for pattern in dangerous_patterns:
        if pattern in target:
            logger.warning(f"Blocked target with injection pattern: {pattern}")
            return False, "", "Invalid target: contains forbidden pattern"
    
    
    if '\x00' in target:
        logger.warning("Blocked target with null byte")
        return False, "", "Invalid target: contains null byte"
    
    
    host, port = extract_host_and_port(target)
    
    if not host:
        return False, "", "Invalid target: no host found"
    
    
    if len(host) > 253:
        return False, "", "Invalid target: host too long"
    
    
    if is_blocked_hostname(host):
        logger.warning(f"Blocked access to forbidden host: {host}")
        return False, "", "Invalid target: host is blocked"
    
    
    is_ip = validate_ip_format(host)
    is_domain = validate_domain_format(host)
    
    if not is_ip and not is_domain:
        return False, "", "Invalid target: not a valid domain or IP"
    
    
    dns_ok, dns_error = dns_resolve(host)
    if not dns_ok:
        logger.warning(f"DNS resolution failed for {host}: {dns_error}")
        return False, "", f"DNS resolution failed: {dns_error}"
    
    
    if require_ping:
        ping_ok, ping_error = ping_host(host)
        if not ping_ok:
            
            
            logger.info(f"Ping failed for {host}: {ping_error} (DNS OK, continuing)")
    
    return True, host, ""
