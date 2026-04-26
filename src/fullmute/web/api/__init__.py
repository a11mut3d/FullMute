from fastapi import APIRouter

from fullmute.web.api import auth, targets, scans, reports, dashboard, settings, admin

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(targets.router, prefix="/targets", tags=["Targets"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_router.include_router(settings.router, prefix="/settings", tags=["Settings"])
api_router.include_router(admin.router, prefix="/admin/global-settings", tags=["Admin"])
