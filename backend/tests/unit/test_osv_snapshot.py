"""OsvSnapshotIndex: загрузка снапшота из артефактори, проверка хеша, устаревание."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from app.adapters.artifact_store import RemoteFile
from app.adapters.vuln_index import OsvSnapshotIndex
from app.core.config import get_settings
from app.core.errors import UpstreamError

RECORD = {
    "id": "GHSA-test-0001",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "vulnpkg"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.3"}]}],
        }
    ],
}
OTHER = {
    "id": "GHSA-test-0002",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "otherpkg"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }
    ],
}


def _snapshot_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("PyPI/GHSA-test-0001.json", json.dumps(RECORD))
        zf.writestr("npm/GHSA-test-0002.json", json.dumps(OTHER))
        zf.writestr("../evil.json", json.dumps({"id": "EVIL"}))  # path traversal
    return buf.getvalue()


@pytest.fixture
def snapshot_store(store):
    s = get_settings()
    payload = _snapshot_bytes()
    key = f"{s.artifact_repo_osv}/{s.osv_snapshot_path}"
    store.files[key] = payload
    store.stats[key] = RemoteFile(
        path=s.osv_snapshot_path,
        size_bytes=len(payload),
        checksum=hashlib.sha256(payload).hexdigest(),
        checksum_algo="sha256",
        last_modified=datetime.now(UTC),
    )
    return store


def test_sync_downloads_and_indexes(tmp_path, snapshot_store):
    index = OsvSnapshotIndex(store=snapshot_store, local_path=str(tmp_path / "osv-db"))
    info = index.sync()
    assert info is not None
    assert info.record_count == 3
    assert index.current_version().version == info.version
    assert index.local_db_path()

    findings = index.query("pypi", "vulnpkg", "1.2.0")
    assert [f.external_id for f in findings] == ["GHSA-test-0001"]
    assert index.query("pypi", "vulnpkg", "1.4.3") == []
    assert index.query("pypi", "unknown", "1.0.0") == []


def test_sync_is_idempotent(tmp_path, snapshot_store):
    index = OsvSnapshotIndex(store=snapshot_store, local_path=str(tmp_path / "osv-db"))
    assert index.sync() is not None
    assert index.sync() is None  # тот же снапшот — no-op


def test_sync_force_redownloads(tmp_path, snapshot_store):
    index = OsvSnapshotIndex(store=snapshot_store, local_path=str(tmp_path / "osv-db"))
    index.sync()
    assert index.sync(force=True) is not None


def test_checksum_mismatch_rejected(tmp_path, snapshot_store):
    s = get_settings()
    key = f"{s.artifact_repo_osv}/{s.osv_snapshot_path}"
    snapshot_store.stats[key].checksum = "0" * 64
    index = OsvSnapshotIndex(store=snapshot_store, local_path=str(tmp_path / "osv-db"))
    with pytest.raises(UpstreamError, match="Контрольная сумма"):
        index.sync()


def test_missing_snapshot_reports_error(tmp_path, store):
    index = OsvSnapshotIndex(store=store, local_path=str(tmp_path / "osv-db"))
    with pytest.raises(UpstreamError, match="Снапшот базы OSV не найден"):
        index.sync()


def test_query_without_snapshot_fails(tmp_path, store):
    index = OsvSnapshotIndex(store=store, local_path=str(tmp_path / "empty"))
    with pytest.raises(UpstreamError, match="не загружена"):
        index.query("pypi", "vulnpkg", "1.0.0")


def test_path_traversal_member_is_contained(tmp_path, snapshot_store):
    root = tmp_path / "osv-db"
    index = OsvSnapshotIndex(store=snapshot_store, local_path=str(root))
    index.sync()
    assert not (tmp_path / "evil.json").exists()
    assert (root / "evil.json").exists()


def test_staleness(tmp_path, snapshot_store):
    s = get_settings()
    key = f"{s.artifact_repo_osv}/{s.osv_snapshot_path}"
    snapshot_store.stats[key].last_modified = datetime.now(UTC) - timedelta(days=10)
    index = OsvSnapshotIndex(store=snapshot_store, local_path=str(tmp_path / "osv-db"))
    index.sync()
    assert index.is_stale(3) is True
    assert index.is_stale(30) is False


def test_missing_local_index_is_stale(tmp_path, store):
    index = OsvSnapshotIndex(store=store, local_path=str(tmp_path / "nothing"))
    assert index.current_version() is None
    assert index.is_stale(3) is True
