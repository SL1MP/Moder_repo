"""Шаги «Политические баннеры» и «SAST-анализ».

Оба сканируют распакованный артефакт и отдают решение DevSecOps, а не
отклоняют пакет сами. Ключевое правило: недоступный сканер — не «чисто».
"""

from __future__ import annotations

import io
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

from app.adapters.content_scan import SEVERITY_ORDER, YaraBannerScanner
from app.db.models import CodeFinding
from app.pipeline.blockers import pending_blockers
from app.pipeline.runner import run_pipeline
from app.services import decisions
from app.services.artifact_unpack import UnpackLimits, cleanup, unpack_artifact
from tests.factories import make_request, steps_by_code

pytestmark = pytest.mark.usefixtures(
    "policies", "store", "storage", "vuln_index", "notifier", "fake_metadata"
)


# --------------------------------------------------------------- распаковка
def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buf.getvalue()


def test_unpack_reads_regular_archive():
    result = unpack_artifact(_zip_bytes({"pkg/a.py": b"print(1)"}), "pkg.whl")
    try:
        assert result.files == 1
        assert (result.root / "pkg" / "a.py").read_bytes() == b"print(1)"
    finally:
        cleanup(result)


def test_unpack_blocks_path_traversal():
    """Элемент, уводящий за пределы каталога, распакован быть не должен."""
    result = unpack_artifact(_zip_bytes({"../../evil.py": b"x", "ok.py": b"y"}), "pkg.whl")
    try:
        assert result.skipped_unsafe == 1
        assert result.files == 1
    finally:
        cleanup(result)


def test_unpack_skips_symlinks():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        data = b"ok"
        info = tarfile.TarInfo("good.py")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("evil")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)

    result = unpack_artifact(buf.getvalue(), "pkg.tar.gz")
    try:
        assert result.files == 1
        assert result.skipped_unsafe == 1
        assert not (result.root / "evil").exists()
    finally:
        cleanup(result)


def test_unpack_stops_at_limits():
    """Архивная бомба не должна разложиться целиком."""
    payload = _zip_bytes({f"f{n}.bin": b"A" * 100_000 for n in range(50)})
    result = unpack_artifact(
        payload, "bomb.zip", limits=UnpackLimits(max_total_bytes=500_000, max_files=1000)
    )
    try:
        assert result.truncated
        assert result.total_bytes <= 500_000
    finally:
        cleanup(result)


def test_unpack_handles_plain_file():
    """Одиночный файл — не архив, но сканировать его всё равно нужно."""
    result = unpack_artifact(b"console.log(1)", "script.js")
    try:
        assert result.files == 1
        assert "не является архивом" in " ".join(result.notes)
    finally:
        cleanup(result)


def test_unpack_survives_corrupted_archive():
    broken = zlib.compress(b"not really a tar")[:20]
    result = unpack_artifact(broken, "pkg.tar.gz")
    try:
        assert result.files >= 0  # главное — не исключение
    finally:
        cleanup(result)


# --------------------------------------------------------------- YARA
def test_yara_scanner_finds_protestware(tmp_path):
    """Настоящие правила из config/rules.yar на настоящем протестварь-коде."""
    rules = Path(__file__).resolve().parents[3] / "config" / "rules.yar"
    if not rules.exists():  # pragma: no cover - на случай урезанной выкладки
        pytest.skip("config/rules.yar не найден")

    (tmp_path / "app.js").write_text(
        "if (navigator.language === 'ru') { showNoWarMessageForRussians(); }",
        encoding="utf-8",
    )
    (tmp_path / "clean.js").write_text("export const add = (a, b) => a + b;", encoding="utf-8")

    outcome = YaraBannerScanner(rules_file=str(rules)).scan(tmp_path)

    assert outcome.available
    assert outcome.findings, "протестварь должен быть найден"
    assert any("sweetalert2" in f.rule_id for f in outcome.findings)
    assert all(f.file == "app.js" for f in outcome.findings), "чистый файл трогать не должны"


def test_yara_scanner_reports_missing_rules(tmp_path):
    outcome = YaraBannerScanner(rules_file=str(tmp_path / "нет.yar")).scan(tmp_path)

    assert not outcome.available
    assert "не найден" in outcome.detail


# --------------------------------------------------------------- шаги
def test_banner_finding_sends_package_to_devsecops(
    session, users, content_scanners, finding_factory_code
):
    content_scanners.banner.findings = [finding_factory_code()]
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["banner_scan"].result == "warn"
    assert "banner_scan" in pending_blockers(item)
    assert item.status == "awaiting_security"
    assert steps["publish"].result != "pass", "с баннером публиковать нельзя"


def test_banner_findings_are_stored(session, users, content_scanners, finding_factory_code):
    content_scanners.banner.findings = [
        finding_factory_code(rule_id="protestware__stop_war", file="pkg/i18n.js", line=42)
    ]
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)
    session.commit()

    stored = session.query(CodeFinding).filter_by(scanner="yara").all()
    assert len(stored) == 1
    assert stored[0].rule_id == "protestware__stop_war"
    assert stored[0].file_path == "pkg/i18n.js"
    assert stored[0].line == 42


def test_clean_package_passes_both_scans(session, users, content_scanners, store):
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["banner_scan"].result == "pass"
    assert steps["sast_scan"].result == "pass"
    assert item.status == "approved"
    assert store.published


def test_unavailable_scanner_does_not_mean_clean(session, users, content_scanners):
    """Нет правил или бинаря — пакет уходит DevSecOps, а не проходит молча."""
    content_scanners.sast.available = False
    content_scanners.sast.detail = "сканер не установлен: semgrep"
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    steps = steps_by_code(item)
    assert steps["sast_scan"].result == "warn"
    assert "не выполнена" in steps["sast_scan"].message
    assert item.status == "awaiting_security"


def test_sast_below_threshold_passes(session, users, content_scanners, finding_factory_code):
    """Порог SAST настраиваемый: находки ниже него не блокируют публикацию."""
    content_scanners.sast.findings = [
        finding_factory_code(scanner="semgrep", severity="low", rule_id="python.lang.style")
    ]
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    assert steps_by_code(item)["sast_scan"].result == "pass"
    assert item.status == "approved"


def test_sast_above_threshold_blocks(session, users, content_scanners, finding_factory_code):
    content_scanners.sast.findings = [
        finding_factory_code(scanner="semgrep", severity="critical", rule_id="python.lang.eval")
    ]
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    assert steps_by_code(item)["sast_scan"].result == "warn"
    assert item.status == "awaiting_security"


def test_disabled_step_is_skipped(session, users, content_scanners, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "banner_scan_enabled", False)
    _, item = make_request(session, users["developer"])

    run_pipeline(session, item)

    assert steps_by_code(item)["banner_scan"].result == "pass"
    assert "выключен настройкой" in steps_by_code(item)["banner_scan"].message


def test_devsecops_decision_clears_all_its_checks(
    session, users, content_scanners, finding_factory_code, store
):
    """Одно решение DevSecOps закрывает и уязвимости, и баннеры, и SAST."""
    content_scanners.banner.findings = [finding_factory_code()]
    content_scanners.sast.findings = [
        finding_factory_code(scanner="semgrep", severity="critical", rule_id="python.lang.eval")
    ]
    _, item = make_request(session, users["developer"])
    run_pipeline(session, item)
    assert {"banner_scan", "sast_scan"} <= set(pending_blockers(item))

    decisions.decide_security(
        session, item, approve=True, actor=users["devsecops"], comment="Разобрано, ложное"
    )

    assert pending_blockers(item) == []
    assert item.status == "approved"
    assert store.published


def test_severity_order_is_monotonic():
    """Порядок серьёзности — основа сравнения с порогом."""
    assert SEVERITY_ORDER.index("info") < SEVERITY_ORDER.index("high")
    assert SEVERITY_ORDER.index("high") < SEVERITY_ORDER.index("critical")
