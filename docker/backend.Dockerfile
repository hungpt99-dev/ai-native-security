# syntax=docker/dockerfile:1

# ---------------------------------------------------------------- base image
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/var/sboms /app/var/workspaces \
    && chown -R appuser:appuser /app/var

# ------------------------------------------------------------------ api image
FROM base AS api

USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]

# --------------------------------------------------------------- worker image
# The worker needs the scanner binaries; they are copied from upstream images
# so versions are pinned and no build-time downloads are required.
FROM python:3.12-slim AS scanners

COPY --from=aquasec/trivy:0.65.0 /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=ghcr.io/gitleaks/gitleaks:v8.28.0 /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=anchore/syft:v1.33.0 /syft /usr/local/bin/syft

FROM base AS worker

USER root
COPY --from=scanners /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=scanners /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=scanners /usr/local/bin/syft /usr/local/bin/syft
RUN chmod +x /usr/local/bin/trivy /usr/local/bin/gitleaks /usr/local/bin/syft \
    && pip install --no-cache-dir semgrep==1.183.0 \
    && semgrep --version \
    && trivy --version \
    && gitleaks version \
    && syft version

USER appuser
CMD ["python", "-m", "app.workers.worker"]

# ------------------------------------------------------------- scheduler image
FROM base AS scheduler

USER appuser
CMD ["python", "-m", "app.scheduler.scheduler"]
