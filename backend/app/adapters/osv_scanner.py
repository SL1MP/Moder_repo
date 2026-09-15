"""Запуск osv-scanner по скачанному артефакту в offline-режиме.

Шаг 5 конвейера работает с артефактом, а не с внешним API: архив распаковывается
во временную директорию и передаётся osv-scanner с локальной базой из снапшота
(`--offline --local-db-path`). Если бинарь недоступен или ничего не нашёл в
lock-файлах внутри архива, применяется прямой запрос к :class:`VulnerabilityIndex`
по паре «имя + версия» — решение всё равно принимается по данным снапшота.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # noqa: S404 - вызов локального бинаря osv-scanner
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from app.adapters.vuln_index import VulnerabilityIndex, VulnFinding, finding_from_osv
from app.core.config import get_settings
from app.core.logging import get_logger
from app.managers.versioning import MANAGER_BY_ECOSYSTEM

log = get_logger(__name__)

SCAN_TIMEOUT_SECONDS = 300


@dataclass
class ScanResult:
    findings: list[VulnFinding]
    scanner: str  # osv-scanner | index
    index_version: str | None = None
    details: dict[str, object] | None = None


def scan_artifact(
    *,
    manager: str,
    name: str,
    version: str,
    filename: str,
    payload: bytes,
    index: VulnerabilityIndex,
) -> ScanResult:
    """Сканирует артефакт. Возвращает найденные уязвимости и использованный сканер."""
    info = index.current_version()
    index_version = info.version if info else None
    local_db = index.local_db_path()

    findings: list[VulnFinding] = []
    scanner = "index"
    if local_db and shutil.which(get_settings().osv_scanner_bin):
        try:
            findings = _run_osv_scanner(manager, filename, payload, local_db)
            scanner = "osv-scanner"
        except Exception as exc:  # noqa: BLE001 - падение сканера не должно ронять конвейер
            log.warning("osv-scanner не выполнился, используется прямой запрос к индексу: %s", exc)
            findings = []
            scanner = "index"

    # Прямой запрос по «имя + версия» — основной путь для одиночного пакета:
    # архив реестра обычно не содержит lock-файлов, по которым работает osv-scanner.
    index_findings = index.query(manager, name, version)
    merged: dict[str, VulnFinding] = {f.external_id: f for f in findings}
    for f in index_findings:
        merged.setdefault(f.external_id, f)
    if index_findings and scanner == "index":
        scanner = "index"

    return ScanResult(
        findings=list(merged.values()),
        scanner=scanner,
        index_version=index_version,
        details={"local_db": local_db, "artifact": filename},
    )


def _run_osv_scanner(manager: str, filename: str, payload: bytes, local_db: str) -> list[VulnFinding]:
    bin_path = get_settings().osv_scanner_bin
    with tempfile.TemporaryDirectory(prefix="osv-scan-") as tmp:
        work = Path(tmp)
        archive = work / filename
        archive.write_bytes(payload)
        target = work / "extracted"
        target.mkdir()
        _extract(archive, target)

        cmd = [
            bin_path,
            "--format",
            "json",
            "--offline",
            "--local-db-path",
            local_db,
            "--recursive",
            str(target),
        ]
        proc = subprocess.run(  # noqa: S603 - фиксированный список аргументов
            cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT_SECONDS, check=False
        )
        # exit code 1 = найдены уязвимости, это нормальный результат
        if proc.returncode not in (0, 1) or not proc.stdout.strip():
            raise RuntimeError(f"osv-scanner завершился с кодом {proc.returncode}: {proc.stderr[:300]}")
        return _parse_scanner_output(proc.stdout, manager)


def _parse_scanner_output(stdout: str, default_manager: str) -> list[VulnFinding]:
    data = json.loads(stdout)
    findings: dict[str, VulnFinding] = {}
    for result in data.get("results") or []:
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            ecosystem = (info.get("ecosystem") or "").split(":")[0].lower()
            manager = MANAGER_BY_ECOSYSTEM.get(ecosystem, default_manager)
            version = info.get("version") or ""
            for record in pkg.get("vulnerabilities") or []:
                finding = finding_from_osv(record, manager, version)
                if finding is None:
                    continue
                findings.setdefault(finding.external_id, finding)
    return list(findings.values())


def _extract(archive: Path, target: Path) -> None:
    """Распаковывает артефакт (zip/whl/nupkg/tar.gz) c защитой от path traversal."""
    name = archive.name.lower()
    if name.endswith((".zip", ".whl", ".nupkg", ".egg")):
        with zipfile.ZipFile(archive) as zf:
            for member in zf.infolist():
                dest = _safe_join(target, member.filename)
                if dest is None:
                    continue
                if member.is_dir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, dest.open("wb") as out:
                    shutil.copyfileobj(src, out)
    elif name.endswith((".tar.gz", ".tgz", ".tar", ".tar.bz2")):
        with tarfile.open(archive) as tf:
            for member in tf.getmembers():
                if not (member.isfile() or member.isdir()):
                    continue
                dest = _safe_join(target, member.name)
                if dest is None:
                    continue
                if member.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                with extracted as src, dest.open("wb") as out:
                    shutil.copyfileobj(src, out)
    else:
        shutil.copy2(archive, target / archive.name)


def _safe_join(root: Path, member: str) -> Path | None:
    candidate = (root / member).resolve()
    if not str(candidate).startswith(str(root.resolve())):
        log.warning("подозрительный путь в архиве пропущен", extra={"member": member})
        return None
    return candidate
