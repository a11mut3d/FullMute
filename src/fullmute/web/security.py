from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import re
import html
from fullmute.utils.logger import setup_logger

logger = setup_logger()


class SecurityMiddleware(BaseHTTPMiddleware):

    
    SQL_INJECTION_PATTERNS = [
        r"(\bSELECT\b.*\bFROM\b)",
        r"(\bINSERT\b.*\bINTO\b)",
        r"(\bUPDATE\b.*\bSET\b)",
        r"(\bDELETE\b.*\bFROM\b)",
        r"(\bDROP\b.*\b(TABLE|DATABASE|INDEX)\b)",
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bOR\b\s+\d+\s*=\s*\d+)",
        r"(\bAND\b\s+\d+\s*=\s*\d+)",
        r"(--|\
        r"(\bEXEC\b|\bEXECUTE\b)",
        r"(\bxp_|\bsp_)",  
        r"(\bWAITFOR\b.*\bDELAY\b)",  
        r"(\bBENCHMARK\b)",  
        r"(\bSLEEP\b\s*\()",
        r"(\bLOAD_FILE\b)",
        r"(\bINTO\s+OUTFILE\b|\bINTO\s+DUMPFILE\b)",
        r"(;\s*DROP)",
        r"('\s*OR\s*')",
        r'("\s*OR\s*")',
    ]

    XSS_PATTERNS = [
        r"<\s*script",
        r"<\s*/\s*script\s*>",
        r"javascript\s*:",
        r"vbscript\s*:",
        r"data\s*:\s*text/html",
        r"on\w+\s*=",  
        r"<\s*img[^>]+onerror",
        r"<\s*svg[^>]+onload",
        r"<\s*iframe",
        r"<\s*object",
        r"<\s*embed",
        r"<\s*link[^>]+href\s*=\s*['\"]?javascript",
        r"<\s*meta[^>]+http-equiv\s*=\s*['\"]?refresh",
        r"expression\s*\(",
        r"url\s*\(\s*['\"]?javascript",
        r"&
        r"%3C\s*script",  
        r"<\s*body[^>]+onload",
        r"<\s*form[^>]+action\s*=\s*['\"]?javascript",
        r"document\.(cookie|location|write)",
        r"window\.(location|open)",
        r"eval\s*\(",
        r"alert\s*\(",
        r"prompt\s*\(",
        r"confirm\s*\(",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e[/%5c]",
        r"%252e%252e",
        r"\.\.%2f",
        r"\.\.%5c",
        r"etc/passwd",
        r"etc/shadow",
        r"windows/system32",
        r"boot\.ini",
        r"win\.ini",
    ]

    COMMAND_INJECTION_PATTERNS = [
        r";\s*\w+",
        r"\|\s*\w+",
        r"\|\|\s*\w+",
        r"&&\s*\w+",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"\$\{[^}]+\}",
        r">\s*/",
        r"<\s*/",
        r"/bin/(bash|sh|zsh|csh)",
        r"\bwget\b",
        r"\bcurl\b",
        r"\bnc\b",
        r"\bnetcat\b",
        r"\bcat\b.*(/etc|/proc)",
    ]

    async def dispatch(self, request, call_next):
        path = request.url.path
        
        
        
        
        
        
        
        EXCLUDED_PATHS = [
            '/api/',           
            '/static/',        
            '/docs',           
            '/redoc',          
            '/openapi.json',   
            '/login',          
        ]
        
        for excluded in EXCLUDED_PATHS:
            if path.startswith(excluded):
                return await call_next(request)
        
        
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            try:
                body = await request.body()
                if body:
                    body_str = body.decode('utf-8', errors='ignore')
                    if self._check_command_injection(body_str):
                        logger.warning(f"Blocked command injection in body for {path}")
                        return JSONResponse(
                            status_code=400,
                            content={"detail": "Potentially malicious content detected"}
                        )
            except Exception as e:
                logger.debug(f"Error reading body: {e}")
                pass  

        
        if self._check_path_traversal(path):
            logger.warning(f"Blocked path traversal attempt: {path}")
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid path"}
            )

        
        for key, value in request.query_params.items():
            
            if self._check_sql_injection(value):
                logger.warning(f"Blocked SQL injection in {key}")
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid parameter"}
                )

            
            if self._check_xss(value):
                logger.warning(f"Blocked XSS in {key}")
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid parameter"}
                )

            
            if self._check_command_injection(value):
                logger.warning(f"Blocked command injection in {key}")
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid parameter"}
                )

        
        
        
        response = await call_next(request)
        return response

    def _check_path_traversal(self, path: str) -> bool:
        path_lower = path.lower()
        
        
        dangerous_patterns = ['../', '..\\', '%2e%2e', '%252e']
        if any(p in path_lower for p in dangerous_patterns):
            return True
        
        
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        
        return False

    def _check_sql_injection(self, text: str) -> bool:
        if not text:
            return False
            
        text_lower = text.lower()
        
        
        quick_checks = [
            'select', 'insert', 'update', 'delete', 'drop',
            'union', 'exec', 'execute', '--', ';--',
            "' or '", '" or "', "' or 1", '" or 1',
            "1=1", "1'='1", '1"="1'
        ]
        
        if any(qc in text_lower for qc in quick_checks):
            
            for pattern in self.SQL_INJECTION_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
        
        return False

    def _check_xss(self, text: str) -> bool:
        if not text:
            return False
            
        text_lower = text.lower()
        
        
        quick_checks = [
            '<script', 'javascript:', 'onerror=', 'onload=',
            'onclick=', 'onmouseover=', '<img', '<svg',
            'alert(', 'document.cookie', 'eval('
        ]
        
        if any(qc in text_lower for qc in quick_checks):
            
            for pattern in self.XSS_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
        
        return False

    def _check_command_injection(self, text: str) -> bool:
        if not text:
            return False
            
        for pattern in self.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
