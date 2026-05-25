"""
FullMute Web Application
FastAPI-based web interface for FullMute scanner
Optimized for stability and performance
"""
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import uvicorn
import gc
import time
import os
import asyncio

from fullmute.web.config import config
from fullmute.web.database import init_web_db, close_thread_db_connection
from fullmute.web.scheduler import init_scheduler
from fullmute.web.api import api_router
from fullmute.web.auth import get_optional_user


import jinja2
from jinja2.environment import Environment
from fullmute.utils.logger import setup_logger
import traceback

# Сохраняем оригинальные методы
_original_load_template = Environment._load_template
_original_get_template = Environment.get_template

def _fixed_load_template(self, name, globals=None):
    logger = setup_logger()
    # Если name не строка — логируем и приводим к безопасному значению
    if not isinstance(name, str):
        logger.warning(f"Non-string template name detected in _load_template: {repr(name)}")
        logger.debug("".join(traceback.format_stack(limit=10)))
        name = str(name) if not isinstance(name, dict) else "dashboard.html"
    return _original_load_template(self, name, globals)

def _fixed_get_template(self, name, parent=None, globals=None):
    logger = setup_logger()
    if not isinstance(name, str):
        logger.warning(f"Non-string template name detected in get_template: {repr(name)}")
        logger.debug("".join(traceback.format_stack(limit=10)))
        name = str(name) if not isinstance(name, dict) else "dashboard.html"
    return _original_get_template(self, name, parent, globals)

Environment._load_template = _fixed_load_template
Environment.get_template = _fixed_get_template

jinja2.Environment.cache_size = 100



app = FastAPI(
    title="FullMute Web",
    description="Modern web interface for FullMute web scanner",
    version="1.2.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)


allowed_origins = os.getenv('FULLMUTE_ALLOWED_ORIGINS', 'http://localhost:8080').split(',')

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


from fullmute.web.security import SecurityMiddleware
app.add_middleware(SecurityMiddleware)


from fullmute.web.csrf_middleware import CSRFMiddleware
app.add_middleware(CSRFMiddleware, secret_key=config.secret_key)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception as e:
        from fullmute.utils.logger import setup_logger
        logger = setup_logger()
        logger.error(f"Request error: {e}")
        raise

    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    if os.getenv('FULLMUTE_PRODUCTION', 'false').lower() == 'true':
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com",
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.gstatic.com",
        "img-src 'self' data: blob:",
        "connect-src 'self' http://localhost:* http://127.0.0.1:*",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
    ]

    response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), "
        "usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
    )

    if request.url.path in ['/login', '/settings', '/api']:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


@app.middleware("http")
async def add_csrf_token_to_context(request: Request, call_next):
    csrf_token = request.cookies.get('csrf_token')

    if not csrf_token:
        from fullmute.web.auth import decode_access_token
        from fullmute.web.csrf import get_csrf_manager

        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            user_data = decode_access_token(auth_header[7:])
            if user_data:
                csrf_manager = get_csrf_manager()
                csrf_token = csrf_manager.generate_token(user_id=user_data['id'])

    request.state.csrf_token = csrf_token or ''
    return await call_next(request)


@app.middleware("http")
async def track_request_time(request: Request, call_next):
    start_time = time.time()

    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(f"{process_time:.3f}")
        return response
    except Exception:
        raise


BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

if hasattr(templates.env, 'cache'):
    templates.env.cache = {}
    from fullmute.utils.logger import setup_logger
    logger = setup_logger()
    logger.debug("Jinja2 template cache cleared on startup")


def render_template(template_name: str, context: dict, status_code: int = 200):
    if not isinstance(template_name, str):
        template_name = "dashboard.html"

    template = templates.get_template(template_name)
    html_content = template.render(context)

    return HTMLResponse(content=html_content, status_code=status_code)


async def periodic_cleanup():
    while True:
        await asyncio.sleep(3600)
        try:
            gc.collect()
            from fullmute.utils.logger import setup_logger
            logger = setup_logger()
            logger.debug("Periodic garbage collection completed")
        except Exception as e:
            pass


@app.on_event("startup")
async def startup_event():
    from fullmute.utils.logger import setup_logger
    logger = setup_logger()

    logger.info("Starting FullMute Web Interface...")

    init_web_db()
    logger.info("Database initialized")

    init_scheduler()
    logger.info("Scheduler initialized")

    from fullmute.web.scan_queue import init_scan_queue_manager
    init_scan_queue_manager()
    logger.info("Scan queue manager initialized")

    asyncio.create_task(periodic_cleanup())
    logger.info("Background cleanup task started")

    print(f"""
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║   FullMute Web Interface Started                      ║
    ║                                                       ║
    ║   Access: http://{config.host}:{config.port:<42}                         ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """)


@app.on_event("shutdown")
async def shutdown_event():
    from fullmute.utils.logger import setup_logger
    logger = setup_logger()

    logger.info("Shutting down FullMute Web Interface...")

    close_thread_db_connection()
    gc.collect()

    logger.info("Shutdown complete")


app.include_router(api_router, prefix="/api")


@app.get("/", response_class=HTMLResponse)
async def root(request: Request, user: dict = Depends(get_optional_user)):
    if user:
        return RedirectResponse(url="/dashboard")
    return RedirectResponse(url="/login")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    context = {
        "request": request,
        "csrf_token": getattr(request.state, 'csrf_token', '')
    }
    return render_template("login.html", context)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, user: dict = Depends(get_optional_user)):
    if not user:
        return RedirectResponse(url="/login")
    context = {
        "request": request,
        "user": user,
        "csrf_token": getattr(request.state, 'csrf_token', '')
    }
    return render_template("dashboard.html", context)


@app.get("/targets", response_class=HTMLResponse)
async def targets_page(request: Request, user: dict = Depends(get_optional_user)):
    if not user:
        return RedirectResponse(url="/login")
    context = {
        "request": request,
        "user": user,
        "csrf_token": getattr(request.state, 'csrf_token', '')
    }
    return render_template("targets.html", context)


@app.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request, user: dict = Depends(get_optional_user)):
    if not user:
        return RedirectResponse(url="/login")
    context = {
        "request": request,
        "user": user,
        "csrf_token": getattr(request.state, 'csrf_token', '')
    }
    return render_template("scans.html", context)


@app.get("/scans/new", response_class=HTMLResponse)
async def new_scan_page(request: Request, user: dict = Depends(get_optional_user)):
    if not user:
        return RedirectResponse(url="/login")
    context = {
        "request": request,
        "user": user,
        "csrf_token": getattr(request.state, 'csrf_token', '')
    }
    return render_template("new-scan.html", context)


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail_page(request: Request, scan_id: int, user: dict = Depends(get_optional_user)):
    if not user:
        return RedirectResponse(url="/login")

    from fullmute.web.database import get_scan
    scan = get_scan(
        scan_id=scan_id,
        user_id=user['id'],
        role=user['role'],
        organization_id=user.get('organization_id')
    )

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    context = {
        "request": request,
        "user": user,
        "scan_id": scan_id,
        "user_scan_number": scan.get('user_scan_number', scan_id),
        "csrf_token": getattr(request.state, 'csrf_token', '')
    }
    return render_template("scan-detail.html", context)


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request, user: dict = Depends(get_optional_user)):
    if not user:
        return RedirectResponse(url="/login")
    context = {
        "request": request,
        "user": user,
        "csrf_token": getattr(request.state, 'csrf_token', '')
    }
    return render_template("reports.html", context)


@app.get("/faq", response_class=HTMLResponse)
async def faq_page(request: Request, user: dict = Depends(get_optional_user)):
    if not user:
        return RedirectResponse(url="/login")
    context = {
        "request": request,
        "user": user,
        "csrf_token": getattr(request.state, 'csrf_token', '')
    }
    return render_template("faq.html", context)


@app.get("/user-settings", response_class=HTMLResponse)
async def user_settings_page(request: Request, user: dict = Depends(get_optional_user)):
    if not user:
        return RedirectResponse(url="/login")
    context = {
        "request": request,
        "user": user,
        "csrf_token": getattr(request.state, 'csrf_token', '')
    }
    return render_template("user-settings.html", context)


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user: dict = Depends(get_optional_user)):
    if not user:
        return RedirectResponse(url="/login")
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    context = {
        "request": request,
        "user": user,
        "csrf_token": getattr(request.state, 'csrf_token', '')
    }
    return render_template("settings.html", context)


@app.get("/favicon.ico")
async def favicon():
    return HTMLResponse(content="", status_code=204)


@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    context = {"request": request}
    return render_template("404.html", context, status_code=404)


if __name__ == "__main__":
    uvicorn.run(
        "fullmute.web.app:app",
        host=config.host,
        port=config.port,
        reload=config.debug
    )
