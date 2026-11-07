"""API v1 router aggregation.

Route handlers stay thin: validation/serialisation live here, business logic
lives in the module services. Authentication is enforced once, at the router
level, so a new endpoint cannot accidentally ship unprotected.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_principal
from app.api.v1 import ai as ai_api
from app.api.v1 import (
    ai_findings,
    dashboard,
    findings,
    jobs,
    remediation,
    sbom_monitoring,
    sboms,
    scans,
    system,
)
from app.modules.assets.api import router as assets_router
from app.modules.audit.api import router as audit_router
from app.modules.events.api import router as events_router
from app.modules.incidents.api import router as incidents_router
from app.modules.infrastructure.api import router as infrastructure_router
from app.modules.monitoring.api import router as monitoring_router
from app.modules.threat_intel.api import router as threat_intel_router
from app.modules.vulnerabilities.api import router as intel_router

api_router = APIRouter(dependencies=[Depends(get_principal)])
api_router.include_router(system.router)
api_router.include_router(assets_router)
api_router.include_router(scans.router)
api_router.include_router(sboms.router)
# Continuous SBOM lifecycle routes must be mounted before the generic finding
# routers only if paths could collide; these are distinct by design.
api_router.include_router(sbom_monitoring.router)
api_router.include_router(findings.router)
api_router.include_router(intel_router)
api_router.include_router(events_router)
api_router.include_router(incidents_router)
api_router.include_router(infrastructure_router)
api_router.include_router(threat_intel_router)
api_router.include_router(monitoring_router)
api_router.include_router(audit_router)
api_router.include_router(dashboard.router)
api_router.include_router(jobs.router)
# AI layer: the finding-scoped router must be mounted before the remediation
# router so its "/findings/{id}/..." paths are not shadowed.
api_router.include_router(ai_api.router)
api_router.include_router(ai_findings.router)
api_router.include_router(remediation.router)
