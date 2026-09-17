"""Сканеры содержимого пакета: политические баннеры (YARA) и SAST (semgrep).

Оба работают по одной схеме: артефакт раскладывается во временный каталог
(см. app/services/artifact_unpack.py), сканер проходит по файлам и возвращает
находки. Дальше решение принимает конвейер, а не сканер.

Правило, общее для обоих и намеренно строгое: **недоступный сканер не значит
«чисто»**. Если правила не подложены или бинаря нет, адаптер возвращает
`available=False`, а шаг конвейера отдаёт предупреждение и зовёт DevSecOps.
Молча пропустить пакет мимо проверки нельзя — ровно так же устроен шаг с
базой OSV.
"""

from __future__ import annotations

import json
import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

# Файлы крупнее не сканируем содержимым: YARA на них уходит в таймаут, а
# полезного в минифицированных бандлах и бинарях всё равно мало.
MAX_SCAN_FILE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class CodeFinding:
    """Находка сканера содержимого."""

    scanner: str
    rule_id: str
    severity: str
    message: str
    file: str
    line: int = 1
    matched: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "matched": self.matched,
        }


@dataclass
class ScanOutcome:
    """Результат прогона сканера."""

    available: bool
    detail: str
    findings: list[CodeFinding] = field(default_factory=list)

    @property
    def worst_severity(self) -> str | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)).severity


class ContentScanner(ABC):
    name: str

    @abstractmethod
    def scan(self, root: Path) -> ScanOutcome: ...


# --------------------------------------------------------------- баннеры (YARA)
class YaraBannerScanner(ContentScanner):
    """Протестварь и политические баннеры по правилам YARA.

    Правила лежат в `BANNER_RULES_FILE` — это тот же файл, что используется в
    CI-конвейерах модерации, чтобы вердикт не расходился между сервисом и CI.
    """

    name = "yara"

    def __init__(self, rules_file: str | None = None, timeout: int | None = None) -> None:
        s = get_settings()
        self.rules_file = rules_file or s.banner_rules_file
        self.timeout = timeout or s.banner_scan_timeout_seconds
        self._rules = None

    def _compile(self):
        if self._rules is not None:
            return self._rules
        import yara  # локальный импорт: без правил модуль не нужен

        self._rules = yara.compile(filepath=self.rules_file)
        return self._rules

    def scan(self, root: Path) -> ScanOutcome:
        if not Path(self.rules_file).exists():
            return ScanOutcome(
                available=False,
                detail=f"файл правил не найден: {self.rules_file}",
            )
        try:
            rules = self._compile()
        except Exception as exc:  # noqa: BLE001 - битые правила не должны ронять конвейер
            return ScanOutcome(available=False, detail=f"правила не скомпилировались: {exc}")

        findings: list[CodeFinding] = []
        scanned = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                if path.stat().st_size > MAX_SCAN_FILE_BYTES:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            scanned += 1
            try:
                matches = rules.match(data=data, timeout=self.timeout)
            except Exception as exc:  # noqa: BLE001 - таймаут по одному файлу не фатален
                log.debug("YARA не отработала по файлу: %s", exc)
                continue
            for match in matches:
                findings.extend(_yara_findings(match, data, path.relative_to(root)))

        triggered = len({f.rule_id for f in findings})
        return ScanOutcome(
            available=True,
            detail=f"просканировано файлов: {scanned}, правил сработало: {triggered}",
            findings=findings,
        )


def _yara_findings(match, data: bytes, relative: Path) -> list[CodeFinding]:
    """Разворачивает совпадение YARA в находки с номером строки и контекстом."""
    out: list[CodeFinding] = []
    seen: set[tuple[str, int]] = set()
    for string in getattr(match, "strings", []):
        for inst in getattr(string, "instances", []):
            offset = getattr(inst, "offset", 0)
            length = getattr(inst, "matched_length", 0)
            line = data.count(b"\n", 0, offset) + 1
            if (match.rule, line) in seen:
                continue
            seen.add((match.rule, line))
            matched = data[offset : offset + length].decode("utf-8", "replace")
            out.append(
                CodeFinding(
                    scanner="yara",
                    rule_id=match.rule,
                    severity="high",
                    message=f"Совпадение правила «{match.rule}» ({string.identifier})",
                    file=str(relative),
                    line=line,
                    matched=matched[:200],
                )
            )
    if not out:
        # Правило без строк (например, по хешу файла) — находка всё равно есть.
        out.append(
            CodeFinding(
                scanner="yara",
                rule_id=match.rule,
                severity="high",
                message=f"Совпадение правила «{match.rule}» по содержимому файла",
                file=str(relative),
            )
        )
    return out


# --------------------------------------------------------------- SAST (semgrep)
_SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

_PROXY_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
)


def _scanner_env(**extra: str) -> dict[str, str]:
    """Окружение внешнего сканера: без ПУСТЫХ переменных прокси, плюс extra.

    docker-compose прокидывает прокси как ``HTTP_PROXY: ${HTTP_PROXY:-}``, то
    есть в контейнере переменная ЕСТЬ, но пустая, когда прокси не настроен.
    Почти все инструменты читают это как «прокси нет», а semgrep-core (он на
    OCaml) — падает::

        [WARNING]: HTTPS_PROXY was supplied a URI with no scheme; augmenting it as https://
        Fatal error: exception Invalid_argument: No host was provided in URI

    Снаружи это выглядело как «SAST не работает», причём непонятно почему:
    бинарь на месте, правила заданы, а отчёта нет. Пустая переменная и
    отсутствующая означают одно и то же, поэтому пустую просто не передаём.

    Непустые передаются как есть: за правилами ``p/default`` semgrep ходит в
    реестр, и в закрытой сети без прокси он не работает.
    """
    env = {
        name: value
        for name, value in os.environ.items()
        if not (name in _PROXY_VARS and not value.strip())
    }
    env.update(extra)
    return env


class SemgrepSastScanner(ContentScanner):
    """SAST по исходникам пакета. Бинарь внешний — как и osv-scanner."""

    name = "semgrep"

    def __init__(self, binary: str | None = None, rules: str | None = None) -> None:
        s = get_settings()
        self.binary = binary or s.sast_scanner_bin
        self.rules = rules if rules is not None else s.sast_rules
        self.timeout = s.sast_timeout_seconds

    def scan(self, root: Path) -> ScanOutcome:
        command = [
            self.binary,
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--timeout",
            str(self.timeout),
            "--config",
            self.rules,
            str(root),
        ]
        try:
            done = subprocess.run(  # noqa: S603 - бинарь задаётся конфигурацией, не пользователем
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout + 60,
                check=False,
                # Окружение задаём явно: пустые переменные прокси semgrep-core
                # роняют (см. _scanner_env), а телеметрия и проверка версии —
                # сетевые вызовы, которых инструменту цепочки поставок здесь
                # делать незачем. Переменными, а не флагами: незнакомый флаг
                # старый semgrep отвергнет целиком, незнакомую переменную —
                # просто не заметит.
                env=_scanner_env(
                    SEMGREP_SEND_METRICS="off",
                    SEMGREP_ENABLE_VERSION_CHECK="0",
                ),
            )
        except FileNotFoundError:
            return ScanOutcome(available=False, detail=f"сканер не установлен: {self.binary}")
        except subprocess.TimeoutExpired:
            return ScanOutcome(available=False, detail=f"сканер не уложился в {self.timeout} с")

        if not done.stdout.strip():
            detail = (done.stderr or "").strip()[:300] or "пустой ответ сканера"
            return ScanOutcome(available=False, detail=f"сканер не вернул отчёт: {detail}")
        try:
            report = json.loads(done.stdout)
        except json.JSONDecodeError as exc:
            return ScanOutcome(available=False, detail=f"отчёт сканера не разобран: {exc}")

        return ScanOutcome(
            available=True,
            detail=f"правил применено: {len(report.get('paths', {}).get('scanned', [])) or '—'}",
            findings=_semgrep_findings(report, root),
        )


def _semgrep_findings(report: dict, root: Path) -> list[CodeFinding]:
    out: list[CodeFinding] = []
    for entry in report.get("results", []):
        extra = entry.get("extra", {})
        path = entry.get("path", "")
        try:
            relative = str(Path(path).relative_to(root))
        except ValueError:
            relative = path
        out.append(
            CodeFinding(
                scanner="semgrep",
                rule_id=entry.get("check_id", "semgrep"),
                severity=_SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), "medium"),
                message=str(extra.get("message", "")).strip()[:500] or "Срабатывание правила SAST",
                file=relative,
                line=int(entry.get("start", {}).get("line", 1) or 1),
                matched=str(extra.get("lines", "")).strip()[:200],
            )
        )
    return out


# --------------------------------------------------------------- фабрики
_banner: ContentScanner | None = None
_sast: ContentScanner | None = None


def get_banner_scanner() -> ContentScanner:
    global _banner
    if _banner is None:
        _banner = YaraBannerScanner()
    return _banner


def get_sast_scanner() -> ContentScanner:
    global _sast
    if _sast is None:
        _sast = SemgrepSastScanner()
    return _sast


def set_scanners(banner: ContentScanner | None = None, sast: ContentScanner | None = None) -> None:
    """Подмена сканеров (тесты, смена реализации)."""
    global _banner, _sast
    _banner = banner
    _sast = sast
