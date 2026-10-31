"""Import every ORM model so ``Base.metadata`` is complete.

Used by Alembic autogeneration and by tests that create the schema.
"""

from app.database.base import Base
from app.modules.assets.models import Asset, AssetCredential
from app.modules.findings.models import Finding, FindingHistory
from app.modules.sbom.models import Sbom, SbomPackage
from app.modules.scans.models import Scan, ScannerExecution
from app.modules.vulnerabilities.models import (
    Vulnerability,
    VulnerabilityAffectedPackage,
    VulnerabilityReference,
    VulnerabilitySyncHistory,
)
from app.workers.models import Job, Schedule

__all__ = [
    "Base",
    "Asset",
    "AssetCredential",
    "Finding",
    "FindingHistory",
    "Sbom",
    "SbomPackage",
    "Scan",
    "ScannerExecution",
    "Vulnerability",
    "VulnerabilityAffectedPackage",
    "VulnerabilityReference",
    "VulnerabilitySyncHistory",
    "Job",
    "Schedule",
]
