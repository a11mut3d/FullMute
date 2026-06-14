import asyncio
import aiohttp
import re
import hashlib
import base64
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs
from difflib import SequenceMatcher

from fullmute.utils.logger import setup_logger

logger = setup_logger()


BLOCKED_DOMAINS = {
    'github.com', 'www.github.com',
    'gitlab.com', 'www.gitlab.com',
    'bitbucket.org', 'www.bitbucket.org',
    'facebook.com', 'www.facebook.com',
    'twitter.com', 'www.twitter.com', 'x.com', 'www.x.com',
    'instagram.com', 'www.instagram.com',
    'linkedin.com', 'www.linkedin.com',
    'vk.com', 'www.vk.com',
    'telegram.org', 'web.telegram.org',
    'google.com', 'www.google.com',
    'yandex.ru', 'www.yandex.ru', 'yandex.com',
    'bing.com', 'www.bing.com',
    'yahoo.com', 'www.yahoo.com',
    'aws.amazon.com', 'console.aws.amazon.com',
    'cloud.google.com',
    'portal.azure.com',
    'mail.google.com', 'gmail.com',
    'outlook.live.com', 'outlook.com',
    'mail.yandex.ru',
    'mail.ru', 'www.mail.ru',
    'paypal.com', 'www.paypal.com',
    'stripe.com', 'www.stripe.com',
}


def is_blocked_domain(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        if hostname in BLOCKED_DOMAINS:
            return True
        for blocked in BLOCKED_DOMAINS:
            if hostname.endswith(f'.{blocked}'):
                return True
        return False
    except Exception:
        return False


@dataclass
class CredentialPair:
    username: str
    password: str
    description: str = ""
    vendor: str = "generic"


@dataclass
class LoginForm:
    url: str
    action_url: str
    username_field: str
    password_field: str
    additional_fields: Dict[str, str] = field(default_factory=dict)
    method: str = "POST"
    detected_type: str = "form"


def generate_email_variants(username: str, domains: List[str] = None) -> List[str]:
    if domains is None:
        domains = ["example.com", "test.com", "local", "localhost", "admin.local", "site.com", "demo.com"]
    variants = [username]
    for domain in domains[:3]:
        variants.append(f"{username}@{domain}")
    variants.append(f"{username}@example.com")
    variants.append(f"{username}@admin.com")
    return variants


def generate_case_variants(username: str, password: str) -> List[CredentialPair]:
    variants = []
    user_variants = [username, username.capitalize(), username.upper()]
    pwd_variants = [password, password.capitalize(), password.upper()]
    seen = set()
    for user in user_variants:
        for pwd in pwd_variants:
            key = f"{user}:{pwd}"
            if key not in seen:
                variants.append(CredentialPair(
                    username=user,
                    password=pwd,
                    description=f"Case variant of {username}:{password}",
                    vendor="case_variant"
                ))
                seen.add(key)
    return variants


def generate_numbered_variants(username: str, password: str) -> List[CredentialPair]:
    variants = []
    suffixes = ["1", "12", "123", "1234", "01", "001", "2023", "2024", "2025", "2026"]
    seen = set()
    for suffix in suffixes:
        user = f"{username}{suffix}"
        pwd = f"{password}{suffix}"
        key = f"{user}:{pwd}"
        if key not in seen:
            variants.append(CredentialPair(
                username=user,
                password=pwd,
                description=f"Numbered variant {username}{suffix}:{password}{suffix}",
                vendor="numbered_variant"
            ))
            seen.add(key)
        key2 = f"{user}:{password}"
        if key2 not in seen:
            variants.append(CredentialPair(
                username=user,
                password=password,
                description=f"Username numbered {username}{suffix}",
                vendor="numbered_variant"
            ))
            seen.add(key2)
    return variants


DEFAULT_CREDENTIALS_DB = {
    "admin": [
        CredentialPair("admin", "admin", "Default admin", "admin"),
        CredentialPair("admin", "password", "Common password", "admin"),
        CredentialPair("admin", "123456", "Weak password", "admin"),
        CredentialPair("admin", "admin123", "Common variant", "admin"),
        CredentialPair("admin", "", "Empty password", "admin"),
        CredentialPair("administrator", "administrator", "Administrator", "admin"),
        CredentialPair("root", "root", "Root account", "admin"),
        CredentialPair("test", "test", "Test account", "admin"),
    ],
    "wordpress": [
        CredentialPair("admin", "admin", "Default WP", "wordpress"),
        CredentialPair("admin", "password", "Common WP", "wordpress"),
        CredentialPair("administrator", "administrator", "WP administrator", "wordpress"),
        CredentialPair("editor", "editor", "WP editor", "wordpress"),
        CredentialPair("author", "author", "WP author", "wordpress"),
    ],
    "joomla": [
        CredentialPair("admin", "admin", "Default Joomla", "joomla"),
        CredentialPair("administrator", "administrator", "Joomla admin", "joomla"),
    ],
    "drupal": [
        CredentialPair("admin", "admin", "Default Drupal", "drupal"),
        CredentialPair("root", "root", "Drupal root", "drupal"),
    ],
    "cisco": [
        CredentialPair("admin", "admin", "Cisco default", "cisco"),
        CredentialPair("cisco", "cisco", "Cisco credentials", "cisco"),
        CredentialPair("enable", "cisco", "Cisco enable", "cisco"),
    ],
    "mikrotik": [
        CredentialPair("admin", "", "MikroTik default", "mikrotik"),
    ],
    "ubiquiti": [
        CredentialPair("ubnt", "ubnt", "Ubiquiti default", "ubiquiti"),
        CredentialPair("admin", "admin", "Common", "ubiquiti"),
    ],
    "tp-link": [
        CredentialPair("admin", "admin", "TP-Link default", "tp-link"),
    ],
    "d-link": [
        CredentialPair("admin", "", "D-Link default", "d-link"),
        CredentialPair("admin", "admin", "Common", "d-link"),
    ],
    "netgear": [
        CredentialPair("admin", "password", "Netgear default", "netgear"),
        CredentialPair("admin", "1234", "Netgear variant", "netgear"),
    ],
    "hikvision": [
        CredentialPair("admin", "12345", "Hikvision default", "hikvision"),
        CredentialPair("admin", "123456", "Hikvision variant", "hikvision"),
    ],
    "dahua": [
        CredentialPair("admin", "admin", "Dahua default", "dahua"),
    ],
    "axis": [
        CredentialPair("root", "pass", "Axis default", "axis"),
        CredentialPair("admin", "admin", "Axis common", "axis"),
        CredentialPair("root", "root", "Axis root", "axis"),
    ],
    "mysql": [
        CredentialPair("root", "", "MySQL root empty", "mysql"),
        CredentialPair("root", "root", "MySQL root", "mysql"),
        CredentialPair("root", "password", "MySQL common", "mysql"),
    ],
    "postgresql": [
        CredentialPair("postgres", "postgres", "PostgreSQL default", "postgresql"),
    ],
    "generic": [
        CredentialPair("root", "root", "Root default", "generic"),
        CredentialPair("root", "password", "Root common", "generic"),
        CredentialPair("root", "toor", "Root reverse", "generic"),
        CredentialPair("test", "test", "Test account", "generic"),
        CredentialPair("user", "user", "User default", "generic"),
        CredentialPair("guest", "guest", "Guest account", "generic"),
        CredentialPair("operator", "operator", "Operator account", "generic"),
        CredentialPair("manager", "manager", "Manager account", "generic"),
    ],
}

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "admin123", "root", "toor", "pass",
    "test", "guest", "master", "changeme", "welcome",
    "monkey", "dragon", "letmein", "login", "admin",
]

COMMON_LOGIN_PATHS = [
    "/", "/admin", "/admin.php", "/admin/",
    "/login", "/login.php", "/login/",
    "/signin", "/sign-in", "/sign_in",
    "/auth", "/authenticate", "/authentication",
    "/wp-admin", "/wp-login.php",
    "/administrator", "/administrator/",
    "/manager", "/manager/html",
    "/console", "/admin/console",
    "/panel", "/controlpanel", "/cpanel",
    "/user", "/users", "/account",
    "/portal", "/webportal",
    "/dashboard", "/dash",
    "/member", "/members",
    "/siteadmin", "/sysadmin",
    "/phpmyadmin", "/pma",
    "/mysql", "/sqladmin",
]


class DefaultCredentialsChecker:
    def __init__(self, timeout: int = 10, max_attempts: int = 5,
                 content_change_threshold: float = 0.6):
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.content_change_threshold = content_change_threshold
        self.session: Optional[aiohttp.ClientSession] = None
        self._tested_hashes: Set[str] = set()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            connector = aiohttp.TCPConnector(
                limit=10,
                ttl_dns_cache=300,
                use_dns_cache=True,
                ssl=False
            )
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=connector,
                cookie_jar=aiohttp.CookieJar()
            )
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            params = parse_qs(parsed.query)
            sorted_params = "&".join(f"{k}={','.join(sorted(v))}" for k, v in sorted(params.items()))
            base += f"?{sorted_params}"
        return base

    def _content_similarity(self, content1: str, content2: str) -> float:
        if not content1 or not content2:
            return 0.0
        return SequenceMatcher(None, content1, content2).ratio()

    def _has_significant_change(self, original: str, new: str) -> bool:
        if not original or not new:
            return True
        similarity = self._content_similarity(original, new)
        change_ratio = 1.0 - similarity
        return change_ratio > self.content_change_threshold

    async def detect_login_forms(self, url: str, html: str) -> List[LoginForm]:
        """Detect traditional <form> login forms and simple JS-based login endpoints.

        Also scans inline scripts for fetch/XMLHttpRequest calls that reference possible
        login endpoints and for JS that references username/password field names.
        """
        forms = []
        if not html:
            return forms

        # First: detect standard <form> elements containing a password input
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)

        for form_html in form_matches:
            if not re.search(r'type=["\']?password["\']?', form_html, re.IGNORECASE):
                continue

            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""
            action_url = urljoin(url, action) if action else url

            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = (method_match.group(1) if method_match else "POST").upper()

            username_field = None
            username_patterns = [
                r'<input[^>]*name=["\']([^"\']*username[^"\']*)["\'][^>]*>',
                r'<input[^>]*name=["\']([^"\']*user[^"\']*)["\'][^>]*>',
                r'<input[^>]*name=["\']([^"\']*email[^"\']*)["\'][^>]*>',
                r'<input[^>]*name=["\']([^"\']*login[^"\']*)["\'][^>]*>',
            ]
            for pattern in username_patterns:
                match = re.search(pattern, form_html, re.IGNORECASE)
                if match:
                    username_field = match.group(1)
                    break

            if not username_field:
                text_input = re.search(
                    r'<input[^>]*type=["\']?text["\']?[^>]*name=["\']([^"\']+)["\']',
                    form_html, re.IGNORECASE
                )
                if text_input:
                    username_field = text_input.group(1)

            password_field = None
            pwd_match = re.search(
                r'<input[^>]*type=["\']?password["\']?[^>]*name=["\']([^"\']+)["\']',
                form_html, re.IGNORECASE
            )
            if pwd_match:
                password_field = pwd_match.group(1)

            if not username_field or not password_field:
                continue

            additional_fields = {}
            hidden_matches = re.findall(
                r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
                form_html, re.IGNORECASE
            )
            for name, value in hidden_matches:
                additional_fields[name] = value

            forms.append(LoginForm(
                url=url,
                action_url=action_url,
                username_field=username_field,
                password_field=password_field,
                additional_fields=additional_fields,
                method=method,
                detected_type="form"
            ))

        # If no traditional forms found, try to heuristically detect JS-driven logins
        if not forms:
            # collect inline scripts
            script_pattern = r'<script[^>]*>(.*?)</script>'
            scripts = re.findall(script_pattern, html, re.IGNORECASE | re.DOTALL)

            possible_endpoints = set()
            possible_user_fields = set()
            possible_pass_fields = set()

            # Simple patterns to find endpoints and parameter names in JS
            fetch_pattern = re.compile(r"fetch\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
            xhr_pattern = re.compile(r"open\(\s*['\"](?:POST|GET)['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
            url_assign_pattern = re.compile(r"(?:var|let|const)\s+\w+\s*=\s*['\"](/[^'\"]+)['\"]", re.IGNORECASE)
            param_name_pattern = re.compile(r"(?:username|user|login|email|passwd|password|pwd)\s*[:=]\s*['\"]?(\w+)['\"]?", re.IGNORECASE)
            name_attr_pattern = re.compile(r"getElementsByName\(['\"]([^'\"]+)['\"]\)")
            id_field_pattern = re.compile(r"getElementById\(['\"]([^'\"]+)['\"]\)")

            for script in scripts:
                for m in fetch_pattern.findall(script):
                    possible_endpoints.add(m)
                for m in xhr_pattern.findall(script):
                    possible_endpoints.add(m)
                for m in url_assign_pattern.findall(script):
                    possible_endpoints.add(m)

                # Try to detect parameter/field names referenced in JS
                for m in name_attr_pattern.findall(script):
                    # m may capture the param name or the JS var; include common fallbacks
                    if re.search(r'pass', m, re.IGNORECASE):
                        possible_pass_fields.add(m)
                    else:
                        possible_user_fields.add(m)
                for m in name_attr_pattern.findall(script):
                    pass
                for m in name_attr_pattern.findall(script):
                    pass
                for m in name_attr_pattern.findall(script):
                    pass
                for m in name_attr_pattern.findall(script):
                    pass

                # getElementsByName/id patterns
                for m in name_attr_pattern.findall(script):
                    possible_user_fields.add(m)
                for m in id_field_pattern.findall(script):
                    # IDs often map to fields like 'user', 'passwd'
                    if re.search(r'pass', m, re.IGNORECASE):
                        possible_pass_fields.add(m)
                    else:
                        possible_user_fields.add(m)

            # Also look for inline occurrences in HTML (e.g., data-login-endpoint="/api/login")
            for m in re.findall(r'data-[a-z-]*login["\']?=\s*["\']?([^"\'\s>]+)', html, re.IGNORECASE):
                possible_endpoints.add(m)

            # Normalize endpoints to absolute URLs
            normalized = []
            for ep in possible_endpoints:
                try:
                    if ep.startswith('http'):
                        normalized.append(ep)
                    else:
                        normalized.append(urljoin(url, ep))
                except Exception:
                    continue

            # If we found endpoints, create synthetic LoginForm entries
            for ep in normalized:
                user_field = next(iter(possible_user_fields), 'username')
                pass_field = next(iter(possible_pass_fields), 'password')
                forms.append(LoginForm(
                    url=url,
                    action_url=ep,
                    username_field=user_field,
                    password_field=pass_field,
                    additional_fields={},
                    method='POST',
                    detected_type='js'
                ))

        # Basic Auth detection (HTTP 401)
        # We'll detect it in check_url, not here
        return forms

    async def is_basic_auth(self, url: str) -> bool:
        """Check if URL requires HTTP Basic Authentication."""
        session = await self._get_session()
        try:
            async with session.get(url, ssl=False, allow_redirects=False) as resp:
                if resp.status == 401 and 'Basic' in resp.headers.get('WWW-Authenticate', ''):
                    return True
        except Exception:
            pass
        return False

    async def check_common_paths(self, base_url: str) -> List[str]:
        found_paths = []
        session = await self._get_session()
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in COMMON_LOGIN_PATHS[:15]:
            test_url = urljoin(base, path)
            try:
                async with session.head(test_url, ssl=False, allow_redirects=True) as resp:
                    if resp.status == 200:
                        found_paths.append(test_url)
                    elif resp.status in (405, 501):
                        try:
                            async with session.get(test_url, ssl=False, allow_redirects=True) as gresp:
                                if gresp.status == 200:
                                    found_paths.append(test_url)
                        except Exception:
                            pass
            except Exception:
                try:
                    async with session.get(test_url, ssl=False, allow_redirects=True) as gresp:
                        if gresp.status == 200:
                            found_paths.append(test_url)
                except Exception:
                    continue
        return found_paths

    def _get_relevant_credentials(self, detected_tech: List[str]) -> List[CredentialPair]:
        credentials = []
        seen = set()

        for tech in detected_tech:
            tech_lower = tech.lower()
            for key, creds in DEFAULT_CREDENTIALS_DB.items():
                if key in tech_lower or tech_lower in key:
                    for cred in creds:
                        cred_key = f"{cred.username}:{cred.password}"
                        if cred_key not in seen:
                            credentials.append(cred)
                            seen.add(cred_key)

                        if cred.username in ['admin', 'root', 'test', 'user']:
                            email_variants = generate_email_variants(cred.username)
                            for email in email_variants[:5]:
                                email_cred_key = f"{email}:{cred.password}"
                                if email_cred_key not in seen:
                                    credentials.append(CredentialPair(
                                        username=email,
                                        password=cred.password,
                                        description=f"Email variant of {cred.description}",
                                        vendor=cred.vendor
                                    ))
                                    seen.add(email_cred_key)

                        if cred.username.lower() in ['admin', 'root', 'user']:
                            case_variants = generate_case_variants(cred.username, cred.password)
                            for cv in case_variants[:6]:
                                cv_key = f"{cv.username}:{cv.password}"
                                if cv_key not in seen:
                                    credentials.append(cv)
                                    seen.add(cv_key)

                        if cred.username.lower() in ['admin', 'root', 'test']:
                            numbered_variants = generate_numbered_variants(cred.username, cred.password)
                            for nv in numbered_variants[:8]:
                                nv_key = f"{nv.username}:{nv.password}"
                                if nv_key not in seen:
                                    credentials.append(nv)
                                    seen.add(nv_key)

        for cred in DEFAULT_CREDENTIALS_DB.get("generic", [])[:5]:
            cred_key = f"{cred.username}:{cred.password}"
            if cred_key not in seen:
                credentials.append(cred)
                seen.add(cred_key)

        for cred in DEFAULT_CREDENTIALS_DB.get("admin", [])[:5]:
            cred_key = f"{cred.username}:{cred.password}"
            if cred_key not in seen:
                credentials.append(cred)
                seen.add(cred_key)

        return credentials[:self.max_attempts]

    def _is_successful_login(self, response_text: str, original_text: str,
                             response_url: str, original_url: str,
                             status_code: int) -> Tuple[bool, str, int]:
        score = 0
        reasons = []
        failure_reasons = []

        cms_error_patterns = [
            (r'ERROR: The password you entered for the username', 'WordPress password error'),
            (r'ERROR: Unknown username', 'WordPress unknown user'),
            (r'ERROR: Invalid username', 'WordPress invalid user'),
            (r'Lost your password\?', 'WordPress lost password link'),
            (r'Invalid username or password', 'Generic auth error'),
            (r'Authentication failed', 'Auth failed message'),
            (r'Unrecognized username or password', 'Drupal auth error'),
            (r'Access denied', 'Access denied'),
            (r'Unauthorized', 'Unauthorized'),
            (r'Forbidden', 'Forbidden'),
            (r'Invalid credentials', 'Invalid credentials'),
            (r'Wrong password', 'Wrong password'),
            (r'Incorrect password', 'Incorrect password'),
            (r'Login failed', 'Login failed'),
            (r'Authentication error', 'Auth error'),
        ]
        for pattern, description in cms_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return False, f"Critical failure: {description}", -100

        if status_code == 401:
            return False, "401 Unauthorized", -100
        if status_code == 403:
            return False, "403 Forbidden", -100

        login_form_patterns = [
            (r'<form[^>]*login', 'login form tag'),
            (r'<input[^>]*type=["\']?password["\']?', 'password input field'),
            (r'<input[^>]*name=["\']?log["\']?', 'WordPress log field'),
            (r'<input[^>]*name=["\']?password["\']?', 'password field'),
            (r'<button[^>]*type=["\']?submit["\'][^>]*login', 'login submit button'),
        ]
        original_has_form = any(re.search(p, original_text, re.IGNORECASE) for p, _ in login_form_patterns)
        response_has_form = any(re.search(p, response_text, re.IGNORECASE) for p, _ in login_form_patterns)

        if original_has_form and response_has_form:
            failure_reasons.append("Login form still present")
            score -= 5

        content_changed = self._has_significant_change(original_text, response_text)
        if content_changed:
            if original_text:
                change_ratio = abs(len(response_text) - len(original_text)) / len(original_text)
            else:
                change_ratio = 1.0
            if change_ratio > 0.6:
                score += 5
                reasons.append(f"Content changed significantly ({change_ratio:.0%})")
            elif change_ratio > 0.4:
                score += 3
                reasons.append(f"Content changed moderately ({change_ratio:.0%})")
            elif change_ratio > 0.15:
                score += 1
                reasons.append(f"Content changed slightly ({change_ratio:.0%})")

        size_diff = abs(len(response_text) - len(original_text))
        if size_diff > 30000:
            score += 5
            reasons.append(f"Page size changed by {size_diff/1024:.1f}KB")
        elif size_diff > 10000:
            score += 3
            reasons.append(f"Page size changed by {size_diff/1024:.1f}KB")
        elif size_diff > 5000:
            score += 1
            reasons.append(f"Page size changed by {size_diff/1024:.1f}KB")

        if response_url != original_url:
            redirect_path = urlparse(response_url).path.lower()
            strong_admin_paths = ['/wp-admin', '/administrator', '/admin', '/dashboard', '/panel', '/console', '/manage', '/control', '/backend']
            generic_admin_paths = ['admin', 'dashboard', 'panel', 'console', 'manage', 'control', 'backend', 'cp', 'main']
            if any(kw in redirect_path for kw in strong_admin_paths):
                score += 5
                reasons.append(f"Redirected to admin area: {redirect_path}")
            elif any(kw in redirect_path for kw in generic_admin_paths):
                score += 3
                reasons.append(f"Redirected to possible admin area: {redirect_path}")
            elif status_code in [302, 303, 307]:
                score += 1
                reasons.append(f"Redirect after login ({status_code})")

        strong_indicators = [
            (r'logout', 'Logout link'),
            (r'log\s*out', 'Log out link'),
            (r'sign\s*out', 'Sign out link'),
            (r'logoff', 'Logoff link'),
            (r'Howdy,\s*\w+', 'WordPress Howdy greeting'),
            (r'welcome\s+back', 'Welcome back message'),
            (r'logged\s*in', 'Logged in message'),
            (r'login\s*successful', 'Login successful message'),
            (r'authentication\s*successful', 'Auth successful message'),
        ]
        medium_indicators = [
            (r'dashboard', 'Dashboard link'),
            (r'admin\s*panel', 'Admin panel link'),
            (r'control\s*panel', 'Control panel link'),
            (r'wp-admin', 'WordPress admin'),
            (r'administrator', 'Administrator panel'),
            (r'my\s*account', 'My account link'),
            (r'user\s*profile', 'User profile link'),
            (r'edit\s*profile', 'Edit profile link'),
            (r'account\s*settings', 'Account settings'),
            (r'Create\s*New', 'Create new content option'),
            (r'Add\s*New', 'Add new content option'),
            (r'hello\s+,\s*\w+', 'Greeting message'),
        ]
        weak_indicators = [
            (r'welcome', 'Welcome text'),
            (r'home', 'Home link'),
            (r'index', 'Index page'),
            (r'main', 'Main page'),
        ]

        for pattern, description in strong_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                score += 3
                reasons.append(f"{description} (+3)")
        for pattern, description in medium_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                score += 2
                reasons.append(f"{description} (+2)")
        if score < 5:
            for pattern, description in weak_indicators:
                if re.search(pattern, response_text, re.IGNORECASE):
                    score += 1
                    reasons.append(f"{description} (+1)")

        if status_code == 200 and score > 0:
            score += 1
            reasons.append("HTTP 200 OK (+1)")

        custom_admin_patterns = [
            (r'<title>[^<]*admin[^<]*</title>', 'Admin in title'),
            (r'<title>[^<]*dashboard[^<]*</title>', 'Dashboard in title'),
            (r'<title>[^<]*panel[^<]*</title>', 'Panel in title'),
            (r'class=["\'][^"\']*admin[^"\']*["\']', 'Admin CSS class'),
            (r'class=["\'][^"\']*dashboard[^"\']*["\']', 'Dashboard CSS class'),
            (r'id=["\'][^"\']*admin[^"\']*["\']', 'Admin element ID'),
        ]
        custom_admin_count = sum(1 for pattern, _ in custom_admin_patterns
                                 if re.search(pattern, response_text, re.IGNORECASE))
        if custom_admin_count >= 2:
            score += 3
            reasons.append(f"Custom admin panel detected ({custom_admin_count} indicators)")
        elif custom_admin_count == 1:
            score += 1
            reasons.append(f"Possible custom admin panel ({custom_admin_count} indicator)")

        if failure_reasons:
            score -= 3
        if original_has_form and response_has_form:
            score -= 10
            reasons.append("Login form still present (-10)")

        if score >= 12:
            return True, f"SUCCESS (Score: {score}) - " + "; ".join(reasons), score
        elif score >= 7:
            return True, f"POSSIBLE SUCCESS (Score: {score}) - " + "; ".join(reasons), score
        else:
            return False, f"UNLIKELY (Score: {score}) - " + "; ".join(reasons + failure_reasons), score

    async def test_credentials(self, form: LoginForm,
                               credentials: List[CredentialPair],
                               original_html: str = "") -> List[Dict[str, Any]]:
        results = []
        if is_blocked_domain(form.action_url):
            logger.debug(f"Skipping credential test on blocked domain: {form.action_url}")
            return results

        session = await self._get_session()

        if not original_html:
            try:
                async with session.get(form.url, ssl=False, allow_redirects=True) as resp:
                    original_html = await resp.text(errors='backslashreplace')
            except Exception as e:
                logger.debug(f"Failed to fetch original page: {e}")
                original_html = ""

        for i, cred in enumerate(credentials):
            if i > 0:
                await asyncio.sleep(1.0)

            test_hash = hashlib.md5(
                f"{form.action_url}:{cred.username}:{cred.password}".encode()
            ).hexdigest()
            if test_hash in self._tested_hashes:
                logger.debug(f"Skipping duplicate test: {cred.username}")
                continue
            self._tested_hashes.add(test_hash)

            try:
                start_time = asyncio.get_event_loop().time()

                if form.method == "BASIC":
                    auth_str = f"{cred.username}:{cred.password}"
                    encoded = base64.b64encode(auth_str.encode()).decode()
                    headers = {"Authorization": f"Basic {encoded}"}
                    async with session.get(form.action_url, headers=headers, ssl=False, allow_redirects=True) as resp:
                        response_html = await resp.text(errors='backslashreplace')
                        response_url = str(resp.url)
                        status_code = resp.status
                elif form.method == "GET":
                    params = {
                        form.username_field: cred.username,
                        form.password_field: cred.password
                    }
                    params.update(form.additional_fields)
                    async with session.get(form.action_url, params=params, ssl=False, allow_redirects=True) as resp:
                        response_html = await resp.text(errors='backslashreplace')
                        response_url = str(resp.url)
                        status_code = resp.status
                else:  # POST
                    form_data = aiohttp.FormData()
                    form_data.add_field(form.username_field, cred.username)
                    form_data.add_field(form.password_field, cred.password)
                    for name, value in form.additional_fields.items():
                        form_data.add_field(name, value)
                    async with session.post(form.action_url, data=form_data, ssl=False, allow_redirects=True) as resp:
                        response_html = await resp.text(errors='backslashreplace')
                        response_url = str(resp.url)
                        status_code = resp.status

                elapsed = asyncio.get_event_loop().time() - start_time
                logger.debug(f"Tested {cred.username}: {elapsed:.2f}s")

                is_success, reason, score = self._is_successful_login(
                    response_html, original_html, response_url, form.url, status_code
                )

                if is_success:
                    password_redacted = "*" * min(len(cred.password), 8)
                    logger.warning(
                        f"SUCCESSFUL LOGIN: {form.action_url} | "
                        f"User: {cred.username} | Password: {password_redacted} | "
                        f"Score: {score} | {reason}"
                    )
                    results.append({
                        "success": True,
                        "url": form.action_url,
                        "username": cred.username,
                        "password": cred.password,
                        "description": cred.description,
                        "reason": reason,
                        "score": score,
                        "vendor": cred.vendor
                    })
                    break
                elif score >= 5:
                    password_redacted = "*" * min(len(cred.password), 8)
                    logger.info(
                        f"POSSIBLE LOGIN: {form.action_url} | "
                        f"User: {cred.username} | Password: {password_redacted} | "
                        f"Score: {score} | {reason}"
                    )
            except asyncio.CancelledError:
                logger.debug(f"Cancelled testing {cred.username}")
                break
            except asyncio.TimeoutError:
                logger.debug(f"Timeout testing {cred.username}")
                continue
            except aiohttp.ClientError as e:
                logger.debug(f"Network error testing {cred.username}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Error testing {cred.username}: {e}")
                continue

        return results

    async def check_url(self, url: str, html: str,
                        detected_tech: List[str] = None) -> Dict[str, Any]:
        result = {
            "url": url,
            "paths_checked": 0,
            "forms_found": 0,
            "credentials_tested": 0,
            "successful_logins": [],
            "error": None
        }

        try:
            if is_blocked_domain(url):
                logger.debug(f"Skipping credential check on blocked domain: {url}")
                return result

            # If caller didn't supply HTML, fetch the page so main-page logins are detected
            session = await self._get_session()
            if not html:
                try:
                    async with session.get(url, ssl=False, allow_redirects=True) as resp:
                        html = await resp.text(errors='backslashreplace')
                except Exception:
                    html = ''

            login_paths = await self.check_common_paths(url)
            result["paths_checked"] = len(login_paths)

            # Detect standard forms and simple JS-driven endpoints on the page
            forms = await self.detect_login_forms(url, html)
            result["forms_found"] = len(forms)

            # Add Basic Auth if no forms found
            if not forms:
                is_basic = await self.is_basic_auth(url)
                if is_basic:
                    forms.append(LoginForm(
                        url=url,
                        action_url=url,
                        username_field="username",
                        password_field="password",
                        method="BASIC",
                        detected_type="basic_auth"
                    ))
                    result["forms_found"] = 1

            detected_tech = detected_tech or []
            credentials = self._get_relevant_credentials(detected_tech)
            result["credentials_to_test"] = len(credentials)

            for form in forms:
                login_results = await self.test_credentials(form, credentials, html)
                result["credentials_tested"] += len(credentials)
                if login_results:
                    result["successful_logins"].extend(login_results)

            if not forms and login_paths:
                for path_url in login_paths[:3]:
                    if path_url != url:
                        try:
                            session = await self._get_session()
                            async with session.get(path_url, ssl=False, allow_redirects=True) as resp:
                                path_html = await resp.text(errors='backslashreplace')
                                path_forms = await self.detect_login_forms(path_url, path_html)
                                if not path_forms:
                                    is_basic = await self.is_basic_auth(path_url)
                                    if is_basic:
                                        path_forms.append(LoginForm(
                                            url=path_url,
                                            action_url=path_url,
                                            username_field="username",
                                            password_field="password",
                                            method="BASIC",
                                            detected_type="basic_auth"
                                        ))
                                for path_form in path_forms:
                                    path_results = await self.test_credentials(path_form, credentials, path_html)
                                    result["credentials_tested"] += len(credentials)
                                    if path_results:
                                        result["successful_logins"].extend(path_results)
                                        break
                        except Exception as e:
                            logger.debug(f"Error checking path {path_url}: {e}")

            return result

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Error checking default credentials for {url}: {e}")
            return result

    async def check_multiple_urls(self, urls_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        for i, data in enumerate(urls_data):
            if i > 0:
                await asyncio.sleep(2.0)
            result = await self.check_url(
                data.get('url', ''),
                data.get('html', ''),
                data.get('detected_tech', [])
            )
            results.append(result)
        return results
