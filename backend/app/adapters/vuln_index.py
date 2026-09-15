"""Адаптер базы уязвимостей.

`OsvSnapshotIndex` — боевой режим: снапшот OSV забирается из артефактори тем же
адаптером :class:`ArtifactStore`, проверяется контрольная сумма, содержимое
распаковывается в локальную директорию для offline-режима osv-scanner.
`OsvApiIndex` — только для локальной разработки (`OSV_SOURCE=api`).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.adapters.artifact_store import ArtifactStore, get_artifact_store
from app.core.config import get_settings
from app.core.errors import UpstreamError
from app.core.http import client, request_with_retries
from app.core.logging import get_logger
from app.managers.utils import parse_iso8601
from app.managers.versioning import (
    MANAGER_BY_ECOSYSTEM,
    OSV_ECOSYSTEMS,
    extract_fixed_versions,
    version_is_affected,
)

log = get_logger(__name__)


@dataclass
class VulnFinding:
    external_id: str
    summary: str | None = None
    aliases: list[str] = field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    severity: str | None = None
    url: str | None = None
    affected_ranges: list[dict[str, Any]] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Нормализованный балл 0..100 (CVSS × 10)."""
        return round((self.cvss_score or 0.0) * 10, 1)


@dataclass
class IndexVersionInfo:
    version: str
    source: str
    checksum: str | None = None
    published_at: datetime | None = None
    remote_path: str | None = None
    record_count: int | None = None
    local_path: str | None = None

    def age_days(self, now: datetime | None = None) -> float | None:
        if self.published_at is None:
            return None
        now = now or datetime.now(UTC)
        published = self.published_at
        if published.tzinfo is None:
            published = published.replace(tzinfo=UTC)
        return (now - published).total_seconds() / 86400


class VulnerabilityIndex(ABC):
    """Контракт источника данных об уязвимостях."""

    source: str

    @abstractmethod
    def current_version(self) -> IndexVersionInfo | None:
        """Версия данных, по которой будет вынесено решение."""

    @abstractmethod
    def query(self, manager: str, name: str, version: str) -> list[VulnFinding]:
        """Уязвимости конкретной версии пакета."""

    def is_stale(self, max_days: int, now: datetime | None = None) -> bool:
        info = self.current_version()
        if info is None:
            return True
        age = info.age_days(now)
        return age is not None and age > max_days

    def local_db_path(self) -> str | None:
        """Директория с распакованной базой для offline-режима osv-scanner."""
        return None


# --------------------------------------------------------------------------- CVSS
_CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_none": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_changed": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss_v3_score(vector: str) -> float | None:
    """Базовый балл CVSS v3.x по вектору. Нужен, когда OSV отдаёт вектор без severity."""
    if not vector or "/" not in vector:
        return None
    parts = dict(
        p.split(":", 1) for p in vector.strip().split("/") if ":" in p and not p.startswith("CVSS")
    )
    try:
        scope_changed = parts.get("S") == "C"
        av = _CVSS_METRICS["AV"][parts["AV"]]
        ac = _CVSS_METRICS["AC"][parts["AC"]]
        pr = _CVSS_METRICS["PR_changed" if scope_changed else "PR_none"][parts["PR"]]
        ui = _CVSS_METRICS["UI"][parts["UI"]]
        conf = _CVSS_METRICS["CIA"][parts["C"]]
        integ = _CVSS_METRICS["CIA"][parts["I"]]
        avail = _CVSS_METRICS["CIA"][parts["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - conf) * (1 - integ) * (1 - avail)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = min(impact + exploitability, 10.0)
    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    # round half up до одной десятой
    import math

    return math.ceil(raw * 10) / 10


_SEVERITY_FALLBACK = {"CRITICAL": 9.0, "HIGH": 7.5, "MODERATE": 5.0, "MEDIUM": 5.0, "LOW": 3.0}


def finding_from_osv(record: dict[str, Any], manager: str, version: str) -> VulnFinding | None:
    """Строит находку из записи OSV, если версия попадает в затронутые диапазоны."""
    ecosystem = OSV_ECOSYSTEMS[manager]
    matched: list[dict[str, Any]] = []
    fixed: list[str] = []
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if (pkg.get("ecosystem") or "").split(":")[0].lower() != ecosystem.lower():
            continue
        if not version_is_affected(manager, version, affected):
            continue
        matched.append({"ranges": affected.get("ranges"), "versions": affected.get("versions")})
        fixed.extend(extract_fixed_versions(affected))
    if not matched:
        return None

    vector, score = None, None
    for sev in record.get("severity") or []:
        if sev.get("type", "").startswith("CVSS_V3") and sev.get("score"):
            vector = sev["score"]
            score = cvss_v3_score(vector)
            break
    if score is None:
        for sev in record.get("severity") or []:
            if sev.get("type") == "CVSS_V4" and sev.get("score"):
                vector = sev["score"]
                break
    label = ((record.get("database_specific") or {}).get("severity") or "").upper()
    if score is None and label in _SEVERITY_FALLBACK:
        score = _SEVERITY_FALLBACK[label]

    vid = record.get("id", "")
    return VulnFinding(
        external_id=vid,
        summary=record.get("summary") or record.get("details", "")[:500] or None,
        aliases=list(record.get("aliases") or []),
        cvss_vector=vector,
        cvss_score=score,
        severity=label or None,
        url=next(
            (r.get("url") for r in record.get("references") or [] if r.get("type") == "ADVISORY"),
            f"https://osv.dev/vulnerability/{vid}" if vid else None,
        ),
        affected_ranges=matched,
        fixed_versions=sorted(set(fixed)),
    )


class OsvSnapshotIndex(VulnerabilityIndex):
    """Локальный снапшот OSV, полученный из артефактори. Сеть к osv.dev не используется."""

    source = "snapshot"

    def __init__(self, store: ArtifactStore | None = None, local_path: str | None = None) -> None:
        self.s = get_settings()
        self.store = store or get_artifact_store()
        self.root = Path(local_path or self.s.osv_local_db_path)

    # ------------------------------------------------------------------ версия
    @property
    def _meta_file(self) -> Path:
        return self.root / "snapshot.json"

    def current_version(self) -> IndexVersionInfo | None:
        if not self._meta_file.exists():
            return None
        try:
            data = json.loads(self._meta_file.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return IndexVersionInfo(
            version=data.get("version", "unknown"),
            source=self.source,
            checksum=data.get("checksum"),
            published_at=parse_iso8601(data.get("published_at")),
            remote_path=data.get("remote_path"),
            record_count=data.get("record_count"),
            local_path=str(self.root),
        )

    def local_db_path(self) -> str | None:
        return str(self.root) if self.root.exists() else None

    def remote_version(self) -> IndexVersionInfo | None:
        """Метаданные снапшота в артефактори — по ним решается, нужна ли загрузка."""
        remote = self.store.stat_file(self.s.artifact_repo_osv, self.s.osv_snapshot_path)
        if remote is None:
            return None
        stamp = (remote.last_modified or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
        version = remote.checksum[:16] if remote.checksum else stamp
        return IndexVersionInfo(
            version=version,
            source=self.source,
            checksum=remote.checksum,
            published_at=remote.last_modified,
            remote_path=self.s.osv_snapshot_path,
        )

    # ------------------------------------------------------------------ загрузка
    def sync(self, *, force: bool = False) -> IndexVersionInfo | None:
        """Скачивает снапшот, если появился новее загруженного. Иначе no-op.

        Идемпотентна: повторный вызов с тем же снапшотом ничего не меняет.
        """
        remote = self.remote_version()
        if remote is None:
            raise UpstreamError(
                "Снапшот базы OSV не найден в артефактори: "
                f"{self.s.artifact_repo_osv}/{self.s.osv_snapshot_path}",
                repo=self.s.artifact_repo_osv,
                path=self.s.osv_snapshot_path,
            )
        local = self.current_version()
        if not force and local and local.version == remote.version:
            log.info("снапшот OSV актуален, загрузка не требуется", extra={"version": local.version})
            return None

        payload = self.store.read_file(self.s.artifact_repo_osv, self.s.osv_snapshot_path)
        digest = hashlib.sha256(payload).hexdigest()
        # Хеш сверяем только если артефактори отдал именно sha256 (иначе это ETag/sha1).
        if remote.checksum and len(remote.checksum) == 64 and remote.checksum.lower() != digest:
            raise UpstreamError(
                "Контрольная сумма снапшота OSV не совпала с заявленной в артефактори",
                expected=remote.checksum,
                actual=digest,
            )

        staging = self.root.with_name(self.root.name + ".new")
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True, exist_ok=True)
        archive = staging / "snapshot.zip"
        archive.write_bytes(payload)
        count = self._extract(archive, staging)
        archive.unlink(missing_ok=True)

        info = IndexVersionInfo(
            version=remote.version,
            source=self.source,
            checksum=digest,
            published_at=remote.published_at or datetime.now(UTC),
            remote_path=remote.remote_path,
            record_count=count,
            local_path=str(self.root),
        )
        (staging / "snapshot.json").write_text(
            json.dumps(
                {
                    "version": info.version,
                    "checksum": info.checksum,
                    "published_at": (info.published_at or datetime.now(UTC)).isoformat(),
                    "remote_path": info.remote_path,
                    "record_count": info.record_count,
                },
                ensure_ascii=False,
            ),
            "utf-8",
        )
        if self.root.exists():
            shutil.rmtree(self.root)
        staging.rename(self.root)
        log.info("снапшот OSV загружен", extra={"version": info.version, "records": count})
        return info

    def _extract(self, archive: Path, target: Path) -> int:
        """Распаковывает снапшот в структуру `{ecosystem}/{id}.json`."""
        count = 0
        with zipfile.ZipFile(archive) as zf:
            for member in zf.infolist():
                if member.is_dir() or not member.filename.endswith(".json"):
                    continue
                dest = target / _safe_member_path(member.filename)
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, dest.open("wb") as out:
                    shutil.copyfileobj(src, out)
                count += 1
        if count == 0:
            raise UpstreamError("Снапшот OSV не содержит ни одной записи .json")
        return count

    # ------------------------------------------------------------------ запрос
    def query(self, manager: str, name: str, version: str) -> list[VulnFinding]:
        if not self.root.exists():
            raise UpstreamError(
                "Локальная база OSV не загружена. Запустите синхронизацию снапшота "
                "(задача sync_osv_snapshot)"
            )
        findings: list[VulnFinding] = []
        for record in self._records_for(manager, name):
            finding = finding_from_osv(record, manager, version)
            if finding:
                findings.append(finding)
        return findings

    def _records_for(self, manager: str, name: str) -> list[dict[str, Any]]:
        ecosystem = OSV_ECOSYSTEMS[manager]
        candidates = [
            self.root / ecosystem,
            self.root / ecosystem.lower(),
            self.root,
        ]
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        target = name.lower()
        for base in candidates:
            if not base.is_dir():
                continue
            for path in base.glob("**/*.json"):
                if path.name == "snapshot.json" or path.name in seen:
                    continue
                try:
                    record = json.loads(path.read_text("utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if not _record_mentions(record, ecosystem, target):
                    continue
                seen.add(path.name)
                out.append(record)
            if out:
                break
        return out


def _record_mentions(record: dict[str, Any], ecosystem: str, name: str) -> bool:
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if (pkg.get("ecosystem") or "").split(":")[0].lower() != ecosystem.lower():
            continue
        if (pkg.get("name") or "").lower() == name:
            return True
    return False


def _safe_member_path(name: str) -> str:
    parts = [p for p in Path(name).parts if p not in ("..", "/", "\\")]
    return str(Path(*parts)) if parts else "record.json"


class OsvApiIndex(VulnerabilityIndex):
    """Запросы к api.osv.dev. Только для локальной разработки (`OSV_SOURCE=api`)."""

    source = "api"

    def __init__(self) -> None:
        self.s = get_settings()

    def current_version(self) -> IndexVersionInfo | None:
        return IndexVersionInfo(
            version=f"api:{datetime.now(UTC).date().isoformat()}",
            source=self.source,
            published_at=datetime.now(UTC),
        )

    def is_stale(self, max_days: int, now: datetime | None = None) -> bool:
        return False

    def query(self, manager: str, name: str, version: str) -> list[VulnFinding]:
        payload = {
            "version": version,
            "package": {"name": name, "ecosystem": OSV_ECOSYSTEMS[manager]},
        }
        url = f"{self.s.osv_api_url.rstrip('/')}/v1/query"
        with client() as http:
            resp = request_with_retries("osv-api", lambda: http.post(url, json=payload))
        if resp.status_code >= 400:
            raise UpstreamError(f"api.osv.dev ответил {resp.status_code}", status=resp.status_code)
        findings: list[VulnFinding] = []
        for record in resp.json().get("vulns") or []:
            finding = finding_from_osv(record, manager, version)
            if finding:
                findings.append(finding)
        return findings


_index: VulnerabilityIndex | None = None


def get_vuln_index() -> VulnerabilityIndex:
    global _index
    if _index is None:
        s = get_settings()
        _index = OsvApiIndex() if s.osv_source == "api" else OsvSnapshotIndex()
    return _index


def set_vuln_index(index: VulnerabilityIndex | None) -> None:
    global _index
    _index = index


__all__ = [
    "IndexVersionInfo",
    "MANAGER_BY_ECOSYSTEM",
    "OsvApiIndex",
    "OsvSnapshotIndex",
    "VulnFinding",
    "VulnerabilityIndex",
    "cvss_v3_score",
    "finding_from_osv",
    "get_vuln_index",
    "set_vuln_index",
]
