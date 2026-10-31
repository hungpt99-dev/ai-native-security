"""Application settings.

Configuration is loaded from environment variables (prefix ``ANS_``) and an
optional ``.env`` file. Every deployment-relevant value is configurable; no
secrets are hardcoded.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split_csv(value: Any) -> Any:
    """Allow comma separated strings for list settings (``a,b,c``)."""
    if isinstance(value, str) and not value.strip().startswith("["):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_prefix="ANS_",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------ app
    app_name: str = "AI-Native Security Platform"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    log_level: str = "INFO"
    log_json: bool = True

    # -------------------------------------------------------- infrastructure
    database_url: str = "postgresql+psycopg://security:security@localhost:5432/security"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_pre_ping: bool = True

    # ---------------------------------------------------------- credentials
    # Root secret used to derive the credential encryption key. Override in
    # production. Never logged.
    secret_key: str = "change-me-in-production"
    credential_key: str | None = None

    # ------------------------------------------------------------------ auth
    auth_enabled: bool = False
    api_keys: Annotated[list[str], NoDecode] = Field(default_factory=list)
    #: Optional per-key asset restriction: {"1": ["<asset-uuid>", ...]} maps the
    #: 1-based index in ``api_keys`` to the assets that key may see. A key with no
    #: entry keeps full access (backwards compatible single-tenant default).
    api_key_scopes: Annotated[dict[str, list[str]], NoDecode] = Field(default_factory=dict)
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )

    # --------------------------------------------------------------- storage
    storage_backend: str = "local"
    storage_root: Path = Path("./var/sboms")

    # -------------------------------------------------------------- scanning
    workspace_root: Path = Path("./var/workspaces")
    allowed_git_hosts: Annotated[list[str], NoDecode] = ["github.com", "gitlab.com"]
    git_clone_timeout_seconds: int = 900
    git_clone_depth: int = 1
    scanner_timeout_seconds: int = 1800
    #: Resource ceilings applied to scanner subprocesses (per process).
    scanner_max_memory_mb: int = 8192
    scanner_max_file_size_mb: int = 4096
    scanner_max_processes: int = 512
    max_concurrent_scans: int = 1
    keep_workspaces: bool = False

    trivy_binary: str = "trivy"
    semgrep_binary: str = "semgrep"
    gitleaks_binary: str = "gitleaks"
    syft_binary: str = "syft"
    #: Semgrep ruleset: registry slug (needs network on first run) or a local
    #: rules directory mounted into the worker.
    semgrep_config: str = "p/security-audit"
    #: Worker parallelism for Semgrep. High core counts on small VPS instances
    #: otherwise exhaust memory ("engine was killed").
    semgrep_jobs: int = 2
    #: SBOM output format: cyclonedx-json or spdx-json.
    sbom_format: str = "cyclonedx-json"

    scanners_enabled: Annotated[list[str], NoDecode] = ["trivy", "semgrep", "gitleaks", "syft"]

    # ----------------------------------------------------- vulnerability intel
    osv_api_url: str = "https://api.osv.dev"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None
    nvd_request_delay_seconds: float = 6.0
    nvd_results_per_page: int = 2000
    #: First-run window (NVD requires <= 120 days per request).
    nvd_initial_lookback_days: int = 7
    #: Safety cap so a scheduled sync cannot run unbounded.
    nvd_max_pages_per_sync: int = 20
    kev_catalog_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    http_timeout_seconds: float = 60.0
    http_max_retries: int = 4
    vuln_sync_enabled: bool = True
    osv_sync_interval_minutes: int = 720
    nvd_sync_interval_minutes: int = 1440
    kev_sync_interval_minutes: int = 1440
    scanner_schedule_interval_minutes: int = 240

    # ------------------------------------------------------------------- ai
    # The AI layer is off by default: without a key the platform must behave
    # exactly like Phase 1. Nothing deterministic ever depends on these values.
    ai_enabled: bool = False
    ai_provider: str = "openai"
    ai_model: str = "gpt-4.1-mini"
    ai_api_key: str | None = None
    ai_base_url: str = "https://api.openai.com/v1"
    #: Extra HTTP headers (JSON object) for OpenAI-compatible gateways that
    #: require routing/affinity headers. Never logged.
    ai_extra_headers: Annotated[dict[str, str], NoDecode] = Field(default_factory=dict)
    ai_timeout_seconds: float = 90.0
    ai_max_retries: int = 3
    ai_retry_backoff_seconds: float = 2.0
    ai_requests_per_minute: int = 30
    #: Hard cap on rendered prompt characters (system + evidence).
    ai_max_input_chars: int = 24000
    ai_max_output_tokens: int = 2000
    ai_temperature: float = 0.1
    ai_daily_budget_usd: float = 5.0
    #: Fallback price table used when the provider does not report a cost.
    ai_price_input_per_1k: float = 0.0
    ai_price_output_per_1k: float = 0.0
    #: Data-sharing policy: source snippets may be sent only when enabled.
    ai_allow_source_sharing: bool = True
    ai_max_snippet_chars: int = 1200
    ai_max_snippets: int = 5
    ai_context_max_evidence: int = 40
    ai_context_version: str = "1"
    #: Off by default: prompts may contain repository text. When true the
    #: rendered prompt is redacted and capped before it is stored.
    ai_store_prompts: bool = False
    ai_assistant_max_tool_calls: int = 6
    #: Automatic post-scan analysis of the highest-risk findings.
    ai_auto_analyze: bool = True
    ai_auto_analyze_max_findings: int = 10
    ai_auto_analyze_min_severity: str = "HIGH"

    # ----------------------------------------------------------------- epss
    epss_enabled: bool = True
    epss_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    epss_sync_interval_minutes: int = 1440

    # -------------------------------------------------- code evidence capture
    #: Capture bounded source snippets for findings that have none (Semgrep
    #: already reports the matched lines). Snippets are stored in the finding
    #: metadata so later analysis does not need the deleted workspace.
    capture_code_snippets: bool = True
    max_snippet_lines: int = 40
    max_snippet_files: int = 200

    # ------------------------------------------------------------- scheduler
    scheduler_enabled: bool = True
    scheduler_poll_seconds: int = 30
    worker_poll_seconds: float = 2.0
    worker_heartbeat_seconds: int = 30
    job_stale_after_seconds: int = 3600
    job_max_attempts: int = 3

    @field_validator("api_keys", "allowed_git_hosts", "cors_origins", "scanners_enabled", mode="before")
    @classmethod
    def _parse_lists(cls, value: Any, info: ValidationInfo) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                # An empty variable means "unset": fall back to the documented
                # default rather than an empty allow-list.
                defaults: dict[str, Any] = {
                    "api_keys": [],
                    "allowed_git_hosts": ["github.com", "gitlab.com"],
                    "cors_origins": ["http://localhost:5173"],
                    "scanners_enabled": ["trivy", "semgrep", "gitleaks", "syft"],
                }
                return defaults.get(info.field_name or "", [])
            if stripped.startswith("["):
                return json.loads(stripped)
            return _split_csv(stripped)
        return value

    @field_validator("storage_root", "workspace_root", mode="before")
    @classmethod
    def _expand_path(cls, value: Any) -> Any:
        return Path(str(value)).expanduser()

    @field_validator("ai_extra_headers", "api_key_scopes", mode="before")
    @classmethod
    def _parse_extra_headers(cls, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return {}
            if stripped.startswith("{"):
                return json.loads(stripped)
        return value

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def sync_database_url(self) -> str:
        """SQLAlchemy sync URL (the application uses the sync driver)."""
        return self.database_url


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
