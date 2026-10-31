"""API v1 router aggregation.

Route handlers stay thin: validation/serialisation live here, business logic
lives in the module services. Authentication is enforced once, at the router
level, so a new endpoint cannot accidentally ship unprotected.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_principal
from app.api.v1 import dashboard, findings, jobs, sboms, scans, system
from app.modules.assets.api import router as assets_router
from app.modules.vulnerabilities.api import router as intel_router

api_router = APIRouter(dependencies=[Depends(get_principal)])
api_router.include_router(system.router)
api_router.include_router(assets_router)
api_router.include_router(scans.router)
api_router.include_router(sboms.router)
api_router.include_router(findings.router)
api_router.include_router(intel_router)
api_router.include_router(dashboard.router)
api_router.include_router(jobs.router)
