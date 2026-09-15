from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "true")
os.environ.setdefault("LOCAL_AUTH_ENABLED", "true")
os.environ.setdefault("LOCAL_AUTH_SECRET", "test-secret")
os.environ.setdefault("OSV_SOURCE", "snapshot")
os.environ.setdefault("HTTP_PROXY", "")
os.environ.setdefault("HTTPS_PROXY", "")
os.environ.setdefault("ARTIFACT_BASE_URL", "http://nexus:8081")
os.environ.setdefault("FERNET_KEY", "u1oCJXLPPuS0aChmvOOfrJHhWlKzZ-mZeGCX_2vTF4E=")

# Политики берём из реальных файлов репозитория: интеграционные тесты проверяют и их.
_CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"
os.environ.setdefault("BLACKLIST_FILE", str(_CONFIG_DIR / "blacklist.yml"))
os.environ.setdefault("ALLOWED_LICENSES_FILE", str(_CONFIG_DIR / "licenses.yml"))

from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.adapters.artifact_store import ArtifactStore, RemoteFile, set_artifact_store  # noqa: E402
from app.adapters.content_scan import CodeFinding, ScanOutcome, set_scanners  # noqa: E402
from app.adapters.notifier import InAppNotifier, set_notifier  # noqa: E402
from app.adapters.object_storage import InMemoryObjectStorage, set_object_storage  # noqa: E402
from app.adapters.vuln_index import (  # noqa: E402
    IndexVersionInfo,
    VulnerabilityIndex,
    VulnFinding,
    set_vuln_index,
)
from app.core.config import get_settings  # noqa: E402
from app.core.http import reset_all_breakers  # noqa: E402
from app.core.ratelimit import reset_rate_limits  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.models import User  # noqa: E402
from app.db.session import configure_engine  # noqa: E402
from app.managers.base import PackageRef, RegistryMetadata  # noqa: E402
from app.services.policies import (  # noqa: E402
    Blacklist,
    BlacklistRule,
    LicensePolicy,
    set_policies,
)


# --------------------------------------------------------------------------- БД
@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )

    @event.listens_for(eng, "connect")
    def _fk(dbapi_conn, _record):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(eng)
    configure_engine(eng)
    yield eng
    Base.metadata.drop_all(eng)


@pytest.fixture
def session(engine) -> Iterator[Session]:
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    db = factory()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


# --------------------------------------------------------------------------- пользователи
TEST_PASSWORD = "secret"
_PASSWORD_HASH: str | None = None


def _password_hash() -> str:
    """bcrypt намеренно медленный — считаем хеш один раз на прогон тестов."""
    global _PASSWORD_HASH
    if _PASSWORD_HASH is None:
        from app.core.security import hash_password

        _PASSWORD_HASH = hash_password(TEST_PASSWORD)
    return _PASSWORD_HASH


@pytest.fixture
def users(session: Session) -> dict[str, User]:
    rows = {
        "developer": User(
            username="dev", full_name="Разработчик", roles=["developer"], is_service=True
        ),
        "devsecops": User(username="sec", full_name="DevSecOps", roles=["devsecops"], is_service=True),
        "legal": User(username="legal", full_name="Юрист", roles=["legal"], is_service=True),
        "admin": User(username="admin", full_name="Админ", roles=["admin"], is_service=True),
        "developer2": User(
            username="dev2", full_name="Другой разработчик", roles=["developer"], is_service=True
        ),
    }
    for user in rows.values():
        user.password_hash = _password_hash()
        session.add(user)
    session.commit()
    return rows


# --------------------------------------------------------------------------- адаптеры
class FakeArtifactStore(ArtifactStore):
    """Артефактори в памяти: публикация, чтение файла, снапшот OSV."""

    def __init__(self) -> None:
        self.published: dict[str, bytes] = {}
        self.files: dict[str, bytes] = {}
        self.stats: dict[str, RemoteFile] = {}
        self.fail_publish = False

    def _key(self, ref: PackageRef, filename: str) -> str:
        return f"{ref.manager}/{ref.name}/{ref.raw_version}/{filename}"

    def publish(self, ref: PackageRef, filename: str, data: bytes) -> str:
        if self.fail_publish:
            from app.core.errors import UpstreamError

            raise UpstreamError("Артефактори недоступен (тест)")
        key = self._key(ref, filename)
        self.published[key] = data
        return self.artifact_url(ref, filename)

    def artifact_url(self, ref: PackageRef, filename: str) -> str:
        return f"http://nexus:8081/repository/{ref.manager}-internal/{self._key(ref, filename)}"

    def exists(self, ref: PackageRef, filename: str) -> bool:
        return self._key(ref, filename) in self.published

    def delete(self, ref: PackageRef, filename: str) -> bool:
        return self.published.pop(self._key(ref, filename), None) is not None

    def read_file(self, repo: str, path: str) -> bytes:
        key = f"{repo}/{path}"
        if key not in self.files:
            from app.core.errors import UpstreamError

            raise UpstreamError(f"Нет файла {key}")
        return self.files[key]

    def stat_file(self, repo: str, path: str) -> RemoteFile | None:
        return self.stats.get(f"{repo}/{path}")

    def download(self, url: str) -> bytes:
        for key, data in self.published.items():
            if url.endswith(key):
                return data
        from app.core.errors import UpstreamError

        raise UpstreamError(f"Нет артефакта по URL {url}")


class FakeVulnIndex(VulnerabilityIndex):
    source = "snapshot"

    def __init__(self) -> None:
        self.findings: dict[tuple[str, str, str], list[VulnFinding]] = {}
        self.version = IndexVersionInfo(
            version="test-snapshot-1",
            source="snapshot",
            checksum="c" * 64,
            published_at=datetime.now(UTC),
            record_count=3,
        )
        self.stale = False

    def current_version(self) -> IndexVersionInfo | None:
        return self.version

    def is_stale(self, max_days: int, now: datetime | None = None) -> bool:
        return self.stale

    def query(self, manager: str, name: str, version: str) -> list[VulnFinding]:
        return list(self.findings.get((manager, name, version), []))

    def local_db_path(self) -> str | None:
        return None

    def set_findings(self, manager: str, name: str, version: str, findings: list[VulnFinding]) -> None:
        self.findings[(manager, name, version)] = findings

    def make_old(self, days: int = 10) -> None:
        self.version.published_at = datetime.now(UTC) - timedelta(days=days)
        self.stale = True


@pytest.fixture
def store() -> Iterator[FakeArtifactStore]:
    fake = FakeArtifactStore()
    set_artifact_store(fake)
    yield fake
    set_artifact_store(None)


@pytest.fixture
def storage() -> Iterator[InMemoryObjectStorage]:
    fake = InMemoryObjectStorage(bucket=get_settings().s3_bucket)
    set_object_storage(fake)
    yield fake
    set_object_storage(None)


@pytest.fixture
def vuln_index() -> Iterator[FakeVulnIndex]:
    fake = FakeVulnIndex()
    set_vuln_index(fake)
    yield fake
    set_vuln_index(None)


class FakeContentScanner:
    """Сканер содержимого под контролем теста.

    По умолчанию отрабатывает и ничего не находит. Настоящие YARA и semgrep в
    тестах не запускаются: правил и бинаря в окружении нет, а их отсутствие —
    это законный повод отдать пакет DevSecOps, из-за чего без подмены каждый
    прогон конвейера упирался бы в ручное решение.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.findings: list[CodeFinding] = []
        self.available = True
        self.detail = "проверка выполнена"
        self.scanned_roots: list[str] = []

    def scan(self, root) -> ScanOutcome:
        self.scanned_roots.append(str(root))
        return ScanOutcome(
            available=self.available, detail=self.detail, findings=list(self.findings)
        )


@dataclass
class FakeScanners:
    banner: FakeContentScanner
    sast: FakeContentScanner


@pytest.fixture(autouse=True)
def content_scanners() -> Iterator[FakeScanners]:
    """Автоматически подменяет оба сканера содержимого во всех тестах."""
    pair = FakeScanners(banner=FakeContentScanner("yara"), sast=FakeContentScanner("semgrep"))
    set_scanners(banner=pair.banner, sast=pair.sast)
    yield pair
    set_scanners(None, None)


@pytest.fixture
def finding_factory_code():
    """Находка сканера содержимого."""

    def make(rule_id: str = "protestware__stop_war", severity: str = "high", **kwargs):
        return CodeFinding(
            scanner=kwargs.pop("scanner", "yara"),
            rule_id=rule_id,
            severity=severity,
            message=kwargs.pop("message", "Совпадение правила"),
            file=kwargs.pop("file", "pkg/app.js"),
            line=kwargs.pop("line", 1),
            matched=kwargs.pop("matched", "stop war"),
        )

    return make


@pytest.fixture
def notifier() -> Iterator[InAppNotifier]:
    fake = InAppNotifier()
    set_notifier(fake)
    yield fake
    set_notifier(None)


@pytest.fixture
def policies() -> Iterator[tuple[Blacklist, LicensePolicy]]:
    blacklist = Blacklist(
        rules=[
            BlacklistRule(
                manager="pypi", name="colourama", versions="*", reason="Тайпсквоттинг colorama"
            ),
            BlacklistRule(manager="npm", name="event-stream", versions="==3.3.6", reason="Бэкдор"),
            BlacklistRule(manager=None, name="internal-*", versions="*", reason="Dependency confusion"),
        ],
        loaded_at=datetime.now(UTC),
        path="test",
    )
    licenses = LicensePolicy(
        allowed={
            "mit": {"spdx_id": "MIT", "name": "MIT License", "allowed": True},
            "apache-2.0": {"spdx_id": "Apache-2.0", "name": "Apache 2.0", "allowed": True},
            "bsd-3-clause": {"spdx_id": "BSD-3-Clause", "allowed": True},
        },
        forbidden={"agpl-3.0-only": {"spdx_id": "AGPL-3.0-only", "allowed": False}},
        loaded_at=datetime.now(UTC),
        path="test",
    )
    set_policies(blacklist, licenses)
    yield blacklist, licenses
    set_policies(Blacklist(rules=[]), LicensePolicy())


@pytest.fixture(autouse=True)
def _reset_state():
    reset_all_breakers()
    reset_rate_limits()
    yield
    reset_all_breakers()
    reset_rate_limits()


# --------------------------------------------------------------------------- метаданные реестра
@pytest.fixture
def fake_metadata(monkeypatch):
    """Подменяет обращение к реестру: фиксированные метаданные и тело артефакта."""
    state: dict[str, object] = {
        "published_at": datetime.now(UTC) - timedelta(days=365),
        "license_spdx": "MIT",
        "artifact_url": "https://files.example.org/pkg-1.0.0.tar.gz",
        "artifact_filename": "pkg-1.0.0.tar.gz",
        "payload": b"artifact-bytes-for-test",
        "checksum_algo": "sha256",
        "checksum": None,
    }

    def build(self, ref: PackageRef) -> RegistryMetadata:
        import hashlib

        payload = state["payload"]
        checksum = state["checksum"]
        if checksum is None and state["checksum_algo"]:
            checksum = hashlib.new(str(state["checksum_algo"]), payload).hexdigest()
        return RegistryMetadata(
            name=ref.name,
            version=ref.raw_version,
            published_at=state["published_at"],
            license_spdx=state["license_spdx"],
            license_raw=state["license_spdx"],
            artifact_url=state["artifact_url"],
            artifact_filename=state["artifact_filename"],
            checksum=checksum,
            checksum_algo=state["checksum_algo"],
            size_bytes=len(payload),
        )

    # Патчим каждый плагин: у каждого своя реализация fetch_metadata.
    from app.managers.registry import all_plugins

    for plugin in all_plugins():
        monkeypatch.setattr(type(plugin), "fetch_metadata", build, raising=False)

    def fake_download(url: str, limit: int, manager: str) -> bytes:
        payload = state["payload"]
        if len(payload) > limit:
            from app.core.errors import UpstreamError

            raise UpstreamError("Артефакт больше лимита")
        return payload

    import app.pipeline.steps as steps_module

    monkeypatch.setattr(steps_module, "_download", fake_download)
    return state


@pytest.fixture
def finding_factory():
    def make(external_id: str = "CVE-2024-0001", score: float = 9.8, fixed: list[str] | None = None):
        return VulnFinding(
            external_id=external_id,
            summary="Тестовая уязвимость",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=score,
            severity="CRITICAL",
            url=f"https://osv.dev/vulnerability/{external_id}",
            fixed_versions=fixed or ["2.0.0"],
        )

    return make


# --------------------------------------------------------------------------- API
@pytest.fixture
def api(engine, storage, store, vuln_index, notifier) -> Iterator[Any]:
    """TestClient приложения. Политики загружаются из реальных файлов config/."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def token():
    """Bearer-токен локальной аутентификации для роли (LOCAL_AUTH_ENABLED=true в тестах)."""
    from app.core.security import issue_local_token

    def make(user: User) -> dict[str, str]:
        access, _ttl = issue_local_token(user)
        return {"Authorization": f"Bearer {access}"}

    return make
