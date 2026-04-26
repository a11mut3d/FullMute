import asyncio
import socket
import logging
import paramiko
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from fullmute.utils.logger import setup_logger

logger = setup_logger()


logging.getLogger('paramiko').setLevel(logging.CRITICAL)
logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)



SSH_DEFAULT_CREDS = [
    
    ('root', 'root', 'Default root/root'),
    ('root', 'password', 'Common root password'),
    ('root', 'admin', 'Admin root password'),
    ('root', '123456', 'Weak root password'),
    ('root', 'raspberry', 'Raspberry Pi default'),
    ('admin', 'admin', 'Default admin/admin'),
    ('admin', 'password', 'Common admin password'),
    ('admin', '123456', 'Weak admin password'),
    ('user', 'user', 'Default user/user'),
    ('test', 'test', 'Default test/test'),
    ('oracle', 'oracle', 'Oracle default'),
    ('postgres', 'postgres', 'PostgreSQL default'),
    ('mysql', 'mysql', 'MySQL default'),
    ('ubuntu', 'ubuntu', 'Ubuntu cloud default'),
    ('ec2-user', 'ec2-user', 'AWS EC2 default'),
    ('pi', 'raspberry', 'Raspberry Pi SSH default'),
    ('vagrant', 'vagrant', 'Vagrant default'),
    ('docker', 'docker', 'Docker default'),
    ('support', 'support', 'Support account default'),
    ('guest', 'guest', 'Guest account default'),
]


@dataclass
class SSHCredentialResult:
    username: str
    password: str
    success: bool
    description: str
    error: Optional[str] = None


class SSHCredentialsChecker:
    
    def __init__(self, timeout: int = 10, max_attempts: int = 5):
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.credentials = SSH_DEFAULT_CREDS[:max_attempts]  
    
    async def test_credentials(
        self,
        host: str,
        port: int = 22,
        test_default_credentials: bool = True
    ) -> List[SSHCredentialResult]:
        if not test_default_credentials:
            logger.debug(f"SSH credential testing disabled for {host}:{port}")
            return []
        
        logger.info(f"Testing SSH credentials on {host}:{port}...")
        
        results = []
        semaphore = asyncio.Semaphore(3)  
        
        async def test_single_cred(username: str, password: str, description: str):
            async with semaphore:
                result = await self._test_single_credential(host, port, username, password)
                result.description = description
                
                if result.success:
                    logger.warning(f"SUCCESS: SSH login {host}:{port} - {username}:{password}")
                    results.append(result)
                else:
                    logger.debug(f"Failed: {username}:{password} - {result.error}")
        
        
        tasks = [
            test_single_cred(username, password, description)
            for username, password, description in self.credentials
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        if results:
            logger.warning(f"Found {len(results)} SSH credential(s) for {host}:{port}")
        else:
            logger.info(f"No default SSH credentials found for {host}:{port}")
        
        return results
    
    async def _test_single_credential(
        self,
        host: str,
        port: int,
        username: str,
        password: str
    ) -> SSHCredentialResult:
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            
            def connect_ssh():
                try:
                    client.connect(
                        hostname=host,
                        port=port,
                        username=username,
                        password=password,
                        timeout=self.timeout,
                        allow_agent=False,
                        look_for_keys=False,
                        banner_timeout=self.timeout
                    )
                    return True, None
                except Exception as e:
                    return False, e

            success, error = await asyncio.get_event_loop().run_in_executor(None, connect_ssh)
            
            if success:
                return SSHCredentialResult(
                    username=username,
                    password=password,
                    success=True,
                    description='',
                    error=None
                )
            else:
                
                error_str = str(error)
                error_type = type(error).__name__
                
                if isinstance(error, paramiko.AuthenticationException):
                    logger.debug(f"SSH auth failed for {host}:{port} - {username}:{password}")
                    return SSHCredentialResult(
                        username=username,
                        password=password,
                        success=False,
                        description='',
                        error='Authentication failed'
                    )
                elif isinstance(error, paramiko.SSHException):
                    logger.debug(f"SSH error for {host}:{port} - {username}:{password}: {error_str}")
                    return SSHCredentialResult(
                        username=username,
                        password=password,
                        success=False,
                        description='',
                        error=f'SSH error: {error_str}'
                    )
                elif isinstance(error, (TimeoutError, asyncio.TimeoutError, socket.timeout)):
                    logger.debug(f"SSH timeout for {host}:{port} - {username}:{password}")
                    return SSHCredentialResult(
                        username=username,
                        password=password,
                        success=False,
                        description='',
                        error='Connection timeout'
                    )
                else:
                    logger.debug(f"SSH unexpected error for {host}:{port} - {username}:{password}: {error_type}: {error_str}")
                    return SSHCredentialResult(
                        username=username,
                        password=password,
                        success=False,
                        description='',
                        error=f'{error_type}: {error_str}'
                    )

        except Exception as e:
            
            logger.debug(f"SSH outer exception for {host}:{port} - {username}:{password}: {type(e).__name__}: {e}")
            return SSHCredentialResult(
                username=username,
                password=password,
                success=False,
                description='',
                error=f'Unexpected error: {type(e).__name__}: {str(e)}'
            )

        finally:
            if client:
                try:
                    client.close()
                except:
                    pass


async def test_ssh_credentials(
    host: str,
    port: int = 22,
    test_default_credentials: bool = True,
    timeout: int = 10,
    max_attempts: int = 5
) -> List[Dict]:
    if not test_default_credentials:
        return []
    
    checker = SSHCredentialsChecker(timeout=timeout, max_attempts=max_attempts)
    results = await checker.test_credentials(host, port, test_default_credentials)
    
    
    return [
        {
            'username': r.username,
            'password': r.password,
            'description': r.description,
            'service': 'ssh',
            'port': port
        }
        for r in results if r.success
    ]
