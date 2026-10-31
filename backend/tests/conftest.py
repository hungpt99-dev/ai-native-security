"""Shared pytest fixtures.

Integration tests run against a real PostgreSQL database (``security_test``)
created on demand; the schema comes from the ORM metadata. Each test runs in a
transaction that is rolled back, so tests are isolated and order-independent.
No external network access is required.
"""

from __future__ import annotations

import os

TEST_DATABASE_URL = os.environ.get(
    "ANS_TEST_DATABASE_URL",
    "postgresql+psycopg://security:security@localhost:5432/security_test",
)
# Always override: the suite must never touch a non-test database.
os.environ["ANS_DATABASE_URL"] = TEST_DATABASE_URL
os.environ.setdefault("ANS_SECRET_KEY", "test-secret-key")
os.environ.setdefault("ANS_AUTH_ENABLED", "false")
os.environ.setdefault("ANS_LOG_JSON", "false")
os.environ.setdefault("ANS_STORAGE_ROOT", "/tmp/ans-test-sboms")
os.environ.setdefault("ANS_WORKSPACE_ROOT", "/tmp/ans-test-workspaces")

import uuid  # noqa: E402
from collections.abc import Iterator  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.storage import LocalFileStorage  # noqa: E402
from app.database.base import Base  # noqa: E402
from app.database.models import (  # noqa: E402,F401  - registers metadata
    Asset,
    AssetCredential,
    Finding,
    FindingHistory,
    Job,
    Sbom,
    SbomPackage,
    Scan,
    ScannerExecution,
    Schedule,
    Vulnerability,
    VulnerabilityAffectedPackage,
    VulnerabilityReference,
    VulnerabilitySyncHistory,
)
from app.database.session import get_db  # noqa: E402
from app.main import create_app  # noqa: E402

assert TEST_DATABASE_URL.endswith("_test") or "test" in TEST_DATABASE_URL, (
    "Refusing to run destructive test fixtures against a non-test database"
)


def _ensure_database() -> None:
    admin_url = TEST_DATABASE_URL.rsplit("/", 1)[0] + "/postgres"
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    db_name = TEST_DATABASE_URL.rsplit("/", 1)[1]
    with admin_engine.connect() as connection:
        exists = connection.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": db_name}
        ).scalar()
        if not exists:
            connection.execute(text(f'CREATE DATABASE "{db_name}"'))
    admin_engine.dispose()


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    _ensure_database()
    engine = create_engine(TEST_DATABASE_URL, pool_pre_ping=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def db(engine: Engine) -> Iterator[Session]:
    connection = engine.connect()
    transaction = connection.begin()
    session_factory = sessionmaker(
        bind=connection, expire_on_commit=False, join_transaction_mode="create_savepoint"
    )
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture()
def client(db: Session) -> Iterator[TestClient]:
    app = create_app()

    def override_get_db() -> Iterator[Session]:
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="session", autouse=True)
def _configure_storage(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Point the storage abstraction at a session-scoped temp directory."""
    import app.core.storage as storage_module

    root = tmp_path_factory.mktemp("sboms")
    settings = get_settings()
    settings.storage_root = root
    storage_module._backend = LocalFileStorage(root)


@pytest.fixture()
def storage() -> LocalFileStorage:
    from app.core.storage import get_storage

    backend = get_storage()
    assert isinstance(backend, LocalFileStorage)
    return backend


@pytest.fixture()
def asset_factory(db: Session):
    from app.modules.assets.schemas import AssetCreate
    from app.modules.assets.service import create_asset

    def _create(**overrides) -> Asset:
        payload = AssetCreate(
            name=overrides.pop("name", f"repo-{uuid.uuid4().hex[:6]}"),
            repo_url=overrides.pop("repo_url", f"https://github.com/example/repo-{uuid.uuid4().hex[:6]}"),
            **overrides,
        )
        asset = create_asset(db, payload)
        db.commit()
        return asset

    return _create


@pytest.fixture()
def settings():
    return get_settings()
