"""Клиенты реестров: разбор метаданных, лицензия, дата публикации, хеш артефакта."""

from __future__ import annotations

import base64
import hashlib

import pytest
import respx

from app.core.errors import UpstreamError
from app.managers.registry import get_plugin

PYPI_JSON = {
    "info": {
        "license": "Apache 2.0",
        "classifiers": ["License :: OSI Approved :: Apache Software License"],
        "summary": "HTTP for Humans",
    },
    "urls": [
        {
            "packagetype": "bdist_wheel",
            "python_version": "py3",
            "filename": "requests-2.31.0-py3-none-any.whl",
            "url": "https://files.pythonhosted.org/requests-2.31.0-py3-none-any.whl",
            "upload_time_iso_8601": "2023-05-22T15:12:42.123456Z",
            "digests": {"sha256": "a" * 64},
            "size": 62574,
            "yanked": False,
        },
        {
            "packagetype": "sdist",
            "filename": "requests-2.31.0.tar.gz",
            "url": "https://files.pythonhosted.org/requests-2.31.0.tar.gz",
            "upload_time_iso_8601": "2023-05-22T15:12:44.000000Z",
            "digests": {"sha256": "b" * 64},
        },
    ],
}


@respx.mock
def test_pypi_metadata():
    plugin = get_plugin("pypi")
    ref = plugin.parse_entry("requests==2.31.0")
    respx.get("https://pypi.org/pypi/requests/2.31.0/json").respond(json=PYPI_JSON)

    meta = plugin.fetch_metadata(ref)
    assert meta.license_spdx == "Apache-2.0"
    assert meta.artifact_filename == "requests-2.31.0-py3-none-any.whl"  # предпочитаем wheel
    assert meta.checksum == "a" * 64
    assert meta.checksum_algo == "sha256"
    assert meta.published_at.year == 2023
    assert meta.size_bytes == 62574


@respx.mock
def test_pypi_license_from_classifiers_when_field_empty():
    plugin = get_plugin("pypi")
    ref = plugin.parse_entry("pkg==1.0.0")
    payload = {
        "info": {"license": "", "classifiers": ["License :: OSI Approved :: MIT License"]},
        "urls": [{"packagetype": "sdist", "filename": "p.tar.gz", "url": "u", "digests": {}}],
    }
    respx.get("https://pypi.org/pypi/pkg/1.0.0/json").respond(json=payload)
    assert plugin.fetch_metadata(ref).license_spdx == "MIT"


@respx.mock
def test_pypi_not_found():
    plugin = get_plugin("pypi")
    ref = plugin.parse_entry("nosuch==1.0.0")
    respx.get("https://pypi.org/pypi/nosuch/1.0.0/json").respond(404)
    with pytest.raises(UpstreamError, match="не найден в реестре pypi"):
        plugin.fetch_metadata(ref)


@respx.mock
def test_npm_metadata_integrity_hash():
    plugin = get_plugin("npm")
    ref = plugin.parse_entry("lodash@4.17.21")
    digest = hashlib.sha512(b"tarball").digest()
    integrity = "sha512-" + base64.b64encode(digest).decode()
    respx.get("https://registry.npmjs.org/lodash").respond(
        json={
            "license": "MIT",
            "time": {"4.17.21": "2021-02-20T15:42:16.891Z"},
            "versions": {
                "4.17.21": {
                    "license": "MIT",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                        "integrity": integrity,
                        "shasum": "c" * 40,
                    },
                }
            },
        }
    )
    meta = plugin.fetch_metadata(ref)
    assert meta.license_spdx == "MIT"
    assert meta.artifact_filename == "lodash-4.17.21.tgz"
    assert meta.checksum_algo == "sha512"
    assert meta.checksum == digest.hex()


@respx.mock
def test_npm_scoped_package_url_escaping():
    plugin = get_plugin("npm")
    ref = plugin.parse_entry("@babel/core@7.24.0")
    route = respx.get("https://registry.npmjs.org/%40babel%2fcore").respond(
        json={
            "time": {"7.24.0": "2024-02-28T00:00:00Z"},
            "versions": {"7.24.0": {"license": "MIT", "dist": {"tarball": "http://x/core-7.24.0.tgz"}}},
        }
    )
    meta = plugin.fetch_metadata(ref)
    assert route.called
    assert meta.version == "7.24.0"


@respx.mock
def test_npm_missing_version():
    plugin = get_plugin("npm")
    ref = plugin.parse_entry("lodash@9.9.9")
    respx.get("https://registry.npmjs.org/lodash").respond(json={"versions": {"4.17.21": {}}})
    with pytest.raises(UpstreamError, match="отсутствует в реестре npm"):
        plugin.fetch_metadata(ref)


@respx.mock
def test_go_metadata_escapes_uppercase():
    plugin = get_plugin("go")
    ref = plugin.parse_entry("github.com/Azure/azure-sdk@v1.2.3")
    respx.get("https://proxy.golang.org/github.com/!azure/azure-sdk/@v/v1.2.3.info").respond(
        json={"Version": "v1.2.3", "Time": "2024-01-15T10:00:00Z"}
    )
    respx.get("https://proxy.golang.org/github.com/!azure/azure-sdk/@v/v1.2.3.ziphash").respond(
        text="h1:abcdef="
    )
    meta = plugin.fetch_metadata(ref)
    assert meta.published_at.month == 1
    assert meta.artifact_url.endswith("v1.2.3.zip")
    assert meta.checksum_algo == "h1"
    # Go module proxy не отдаёт лицензию — решение принимают юристы.
    assert meta.license_spdx is None


@respx.mock
def test_go_module_not_found():
    plugin = get_plugin("go")
    ref = plugin.parse_entry("example.com/none@v1.0.0")
    respx.get("https://proxy.golang.org/example.com/none/@v/v1.0.0.info").respond(404)
    with pytest.raises(UpstreamError, match="не найден в go module proxy"):
        plugin.fetch_metadata(ref)


@respx.mock
def test_nuget_metadata_inline_catalog_entry():
    plugin = get_plugin("nuget")
    ref = plugin.parse_entry("Newtonsoft.Json@13.0.3")
    respx.get(
        "https://api.nuget.org/v3/registration5-semver1/newtonsoft.json/13.0.3.json"
    ).respond(
        json={
            "packageContent": "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/n.nupkg",
            "catalogEntry": {
                "licenseExpression": "MIT",
                "published": "2023-03-08T00:00:00Z",
                "listed": True,
            },
        }
    )
    meta = plugin.fetch_metadata(ref)
    assert meta.license_spdx == "MIT"
    assert meta.artifact_filename == "newtonsoft.json.13.0.3.nupkg"
    assert meta.published_at.year == 2023


@respx.mock
def test_nuget_fallback_flatcontainer_url():
    plugin = get_plugin("nuget")
    ref = plugin.parse_entry("Serilog@3.1.1")
    respx.get("https://api.nuget.org/v3/registration5-semver1/serilog/3.1.1.json").respond(
        json={"catalogEntry": {"published": "2023-11-01T00:00:00Z"}}
    )
    meta = plugin.fetch_metadata(ref)
    assert meta.artifact_url.endswith("v3-flatcontainer/serilog/3.1.1/serilog.3.1.1.nupkg")


@respx.mock
def test_retries_then_success():
    from app.core.http import reset_all_breakers

    reset_all_breakers()
    plugin = get_plugin("pypi")
    ref = plugin.parse_entry("flaky==1.0.0")
    route = respx.get("https://pypi.org/pypi/flaky/1.0.0/json")
    route.side_effect = [
        respx.MockResponse(503),
        respx.MockResponse(200, json={"info": {"license": "MIT"}, "urls": []}),
    ]
    meta = plugin.fetch_metadata(ref)
    assert meta.license_spdx == "MIT"
    assert route.call_count == 2


@respx.mock
def test_circuit_breaker_opens_after_failures(monkeypatch):
    from app.core.config import get_settings
    from app.core.errors import CircuitOpenError
    from app.core.http import reset_all_breakers

    monkeypatch.setattr(get_settings(), "circuit_breaker_fail_max", 2)
    monkeypatch.setattr(get_settings(), "http_retries", 1)
    reset_all_breakers()

    plugin = get_plugin("pypi")
    ref = plugin.parse_entry("broken==1.0.0")
    respx.get("https://pypi.org/pypi/broken/1.0.0/json").respond(503)

    with pytest.raises(UpstreamError):
        plugin.fetch_metadata(ref)
    with pytest.raises(CircuitOpenError):
        plugin.fetch_metadata(ref)
    reset_all_breakers()
