"""Import every ORM model so ``Base.metadata`` is complete.

Used by Alembic autogeneration and by tests that create the schema.
"""

from app.database.base import Base
from app.modules.ai.models import AIExecution, InvestigationEvidence, SecurityInvestigation
from app.modules.assets.models import Asset, AssetCredential
from app.modules.findings.models import Finding, FindingHistory
from app.modules.knowledge_base.models import (
    AIFeedback,
    AssistantConversation,
    AssistantMessage,
    SecurityDecision,
)
from app.modules.remediation.models import RemediationRecommendation
from app.modules.risk_analysis.models import RiskAssessment
from app.modules.sbom.models import Sbom, SbomPackage, SbomPackageEdge
from app.modules.scans.models import Scan, ScannerExecution
from app.modules.security_intelligence.models import (
    AssetRepositoryMetadata,
    AssetSecurityProfile,
    SecurityContextSnapshot,
)
from app.modules.security_policies.models import SecurityPolicy
from app.modules.verification.models import RemediationVerification
from app.modules.vulnerabilities.models import (
    Vulnerability,
    VulnerabilityAffectedPackage,
    VulnerabilityEpss,
    VulnerabilityReference,
    VulnerabilitySyncHistory,
)
from app.workers.models import Job, Schedule

__all__ = [
    "Base",
    "Asset",
    "AssetCredential",
    "AssetRepositoryMetadata",
    "AssetSecurityProfile",
    "AIFeedback",
    "AIExecution",
    "AssistantConversation",
    "AssistantMessage",
    "Finding",
    "FindingHistory",
    "InvestigationEvidence",
    "Job",
    "RemediationRecommendation",
    "RemediationVerification",
    "RiskAssessment",
    "Sbom",
    "SbomPackage",
    "SbomPackageEdge",
    "Scan",
    "ScannerExecution",
    "Schedule",
    "SecurityContextSnapshot",
    "SecurityDecision",
    "SecurityInvestigation",
    "SecurityPolicy",
    "Vulnerability",
    "VulnerabilityAffectedPackage",
    "VulnerabilityEpss",
    "VulnerabilityReference",
    "VulnerabilitySyncHistory",
]
