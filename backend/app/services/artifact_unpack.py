"""Безопасная распаковка артефакта для сканирования содержимого.

Пакет из реестра — это архив (wheel и nupkg суть zip, sdist и npm — tar.gz).
Чтобы прогнать по нему YARA и SAST, содержимое надо разложить на диск. Архив
приходит из внешнего мира и доверия не заслуживает, поэтому распаковка
ограничена со всех сторон:

* путь каждого элемента проверяется на выход за пределы каталога (zip-slip);
* символические и жёсткие ссылки пропускаются целиком — внутри пакета они не
  нужны, а увести за пределы каталога могут;
* суммарный распакованный объём, размер одного файла и число файлов ограничены
  (архивная бомба);
* вложенные архивы раскрываются на ограниченную глубину.

Модуль ничего не знает ни о конвейере, ни о сканерах: на вход — байты, на
выход — временный каталог, который вызывающая сторона обязана удалить.
"""

from __future__ import annotations

import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.core.logging import get_logger

log = get_logger(__name__)

NESTED_SUFFIXES = (".zip", ".whl", ".nupkg", ".jar", ".tar", ".tar.gz", ".tgz", ".tar.bz2")


@dataclass
class UnpackLimits:
    """Границы распаковки. Значения по умолчанию рассчитаны на пакет, а не на образ."""

    max_total_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_files: int = 20_000
    max_depth: int = 2


@dataclass
class UnpackResult:
    root: Path
    files: int = 0
    total_bytes: int = 0
    skipped_unsafe: int = 0
    skipped_large: int = 0
    truncated: bool = False  # упёрлись в лимит, разложено не всё
    notes: list[str] = field(default_factory=list)


def _is_within(base: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except (ValueError, OSError):
        return False


def _safe_target(base: Path, name: str) -> Path | None:
    """Путь назначения, если он не выводит за пределы каталога."""
    if not name or name.startswith("/") or ".." in Path(name).parts:
        return None
    target = base / name
    return target if _is_within(base, target) else None


class _Budget:
    """Общий на весь разбор счётчик файлов и объёма."""

    def __init__(self, limits: UnpackLimits, result: UnpackResult) -> None:
        self.limits = limits
        self.result = result

    def allows(self, size: int) -> bool:
        if size > self.limits.max_file_bytes:
            self.result.skipped_large += 1
            return False
        if self.result.files >= self.limits.max_files:
            self.result.truncated = True
            return False
        if self.result.total_bytes + size > self.limits.max_total_bytes:
            self.result.truncated = True
            return False
        return True

    def account(self, size: int) -> None:
        self.result.files += 1
        self.result.total_bytes += size


def _extract_zip(payload: Path, into: Path, budget: _Budget) -> None:
    with zipfile.ZipFile(payload) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            target = _safe_target(into, info.filename)
            if target is None:
                budget.result.skipped_unsafe += 1
                continue
            if not budget.allows(info.file_size):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            budget.account(info.file_size)


def _extract_tar(payload: Path, into: Path, budget: _Budget) -> None:
    with tarfile.open(payload) as archive:
        for member in archive:
            # Ссылки и спец-файлы не распаковываем вовсе: внутри пакета они не
            # нужны, а вывести за пределы каталога способны.
            if not member.isfile():
                if member.issym() or member.islnk():
                    budget.result.skipped_unsafe += 1
                continue
            target = _safe_target(into, member.name)
            if target is None:
                budget.result.skipped_unsafe += 1
                continue
            if not budget.allows(member.size):
                continue
            source = archive.extractfile(member)
            if source is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, open(target, "wb") as dst:
                shutil.copyfileobj(source, dst, length=1024 * 1024)
            budget.account(member.size)


def _extract_any(payload: Path, into: Path, budget: _Budget) -> bool:
    """Раскрывает архив известного вида. False — формат не распознан."""
    try:
        if zipfile.is_zipfile(payload):
            _extract_zip(payload, into, budget)
            return True
        if tarfile.is_tarfile(payload):
            _extract_tar(payload, into, budget)
            return True
    except Exception as exc:  # noqa: BLE001 - битый архив не должен ронять конвейер
        budget.result.notes.append(f"архив не раскрыт ({payload.name}): {exc}")
        log.info("не удалось раскрыть архив", extra={"file": payload.name, "error": str(exc)})
    return False


def _expand_nested(root: Path, budget: _Budget, depth: int) -> None:
    """Раскрывает вложенные архивы: пакет может везти в себе ещё один."""
    if depth >= budget.limits.max_depth:
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if not path.name.lower().endswith(NESTED_SUFFIXES):
            continue
        into = path.with_name(f"{path.name}__unpacked")
        try:
            into.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        if _extract_any(path, into, budget):
            _expand_nested(into, budget, depth + 1)


def unpack_artifact(
    payload: bytes, filename: str, *, limits: UnpackLimits | None = None
) -> UnpackResult:
    """Раскладывает артефакт во временный каталог. Каталог удаляет вызывающий."""
    limits = limits or UnpackLimits()
    root = Path(tempfile.mkdtemp(prefix="moderation-scan-"))
    result = UnpackResult(root=root)
    budget = _Budget(limits, result)

    archive_path = root / "__artifact__"
    archive_path.write_bytes(payload)
    content = root / "content"
    content.mkdir()

    if not _extract_any(archive_path, content, budget):
        # Не архив (например, одиночный .py или .js) — сканируем как файл.
        target = content / (Path(filename).name or "artifact")
        target.write_bytes(payload)
        budget.account(len(payload))
        result.notes.append("артефакт не является архивом — просканирован как один файл")
    else:
        _expand_nested(content, budget, depth=0)

    archive_path.unlink(missing_ok=True)
    result.root = content
    if result.truncated:
        result.notes.append(
            f"распаковка ограничена: {result.files} файлов, "
            f"{result.total_bytes // (1024 * 1024)} МБ — часть содержимого не проверена"
        )
    return result


def cleanup(result: UnpackResult) -> None:
    """Удаляет временный каталог распаковки."""
    shutil.rmtree(result.root.parent, ignore_errors=True)
