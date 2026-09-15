"""Сопоставление версий с диапазонами OSV в каждой экосистеме."""

from __future__ import annotations

import pytest

from app.adapters.vuln_index import cvss_v3_score, finding_from_osv
from app.managers.versioning import (
    compare_go,
    compare_nuget,
    compare_pep440,
    compare_semver,
    sort_versions,
    version_is_affected,
    version_matches_range,
)


# --------------------------------------------------------------------------- компараторы
@pytest.mark.parametrize(
    ("a", "b", "sign"),
    [
        ("1.0.0", "1.0.1", -1),
        ("2.0", "2.0.0", 0),
        ("1.0rc1", "1.0", -1),
        ("1.0.0", "1.0.0.post1", -1),
        ("1!1.0", "2.0", 1),  # epoch важнее
        ("1.0.0a1", "1.0.0b1", -1),
    ],
)
def test_pep440(a, b, sign):
    assert _sign(compare_pep440(a, b)) == sign


@pytest.mark.parametrize(
    ("a", "b", "sign"),
    [
        ("1.0.0", "1.0.1", -1),
        ("1.0.0-rc.1", "1.0.0", -1),
        ("1.0.0-alpha", "1.0.0-alpha.1", -1),
        ("1.0.0-alpha.1", "1.0.0-beta", -1),
        ("1.0.0-1", "1.0.0-alpha", -1),  # числовой идентификатор младше алфавитного
        ("1.0.0+build1", "1.0.0+build2", 0),  # build-метаданные не влияют
        ("2.0.0", "10.0.0", -1),
    ],
)
def test_semver(a, b, sign):
    assert _sign(compare_semver(a, b)) == sign


@pytest.mark.parametrize(
    ("a", "b", "sign"),
    [
        ("v1.9.1", "v1.10.0", -1),
        ("v2.0.0+incompatible", "v2.0.0", 0),
        ("v0.0.0-20240101120000-abcdef123456", "v0.1.0", -1),
        ("v1.0.0-rc1", "v1.0.0", -1),
    ],
)
def test_go(a, b, sign):
    assert _sign(compare_go(a, b)) == sign


@pytest.mark.parametrize(
    ("a", "b", "sign"),
    [
        ("13.0.3", "13.0.10", -1),
        ("1.0", "1.0.0.0", 0),  # NuGet добивает до четырёх компонент
        ("6.0.0-preview.5", "6.0.0", -1),
        ("6.0.0.1", "6.0.0", 1),
        ("1.0.0-alpha", "1.0.0-beta", -1),
    ],
)
def test_nuget(a, b, sign):
    assert _sign(compare_nuget(a, b)) == sign


def test_sort_versions_per_ecosystem():
    assert sort_versions("pypi", ["2.0", "1.0rc1", "1.0"]) == ["1.0rc1", "1.0", "2.0"]
    assert sort_versions("npm", ["1.0.0", "1.0.0-rc.1", "0.9.9"]) == [
        "0.9.9",
        "1.0.0-rc.1",
        "1.0.0",
    ]


def _sign(value: int) -> int:
    return (value > 0) - (value < 0)


# --------------------------------------------------------------------------- диапазоны OSV
INTRODUCED_FIXED = {"events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}
FROM_ZERO = {"events": [{"introduced": "0"}, {"fixed": "1.4.3"}]}
LAST_AFFECTED = {"events": [{"introduced": "1.0.0"}, {"last_affected": "1.9.9"}]}
MULTI = {
    "events": [
        {"introduced": "1.0.0"},
        {"fixed": "1.5.0"},
        {"introduced": "2.0.0"},
        {"fixed": "2.3.0"},
    ]
}


@pytest.mark.parametrize(
    ("manager", "version", "rng", "expected"),
    [
        ("pypi", "1.5.0", INTRODUCED_FIXED, True),
        ("pypi", "2.0.0", INTRODUCED_FIXED, False),
        ("pypi", "0.9", INTRODUCED_FIXED, False),
        ("pypi", "1.4.2", FROM_ZERO, True),
        ("pypi", "1.4.3", FROM_ZERO, False),
        ("npm", "1.9.9", LAST_AFFECTED, True),
        ("npm", "2.0.0", LAST_AFFECTED, False),
        ("npm", "1.4.9", MULTI, True),
        ("npm", "1.5.0", MULTI, False),
        ("npm", "2.2.0", MULTI, True),
        ("npm", "2.3.0", MULTI, False),
        ("go", "v1.4.0", {"events": [{"introduced": "v1.0.0"}, {"fixed": "v1.5.0"}]}, True),
        ("go", "v1.5.0", {"events": [{"introduced": "v1.0.0"}, {"fixed": "v1.5.0"}]}, False),
        ("nuget", "12.0.3", {"events": [{"introduced": "0"}, {"fixed": "13.0.1"}]}, True),
        ("nuget", "13.0.1", {"events": [{"introduced": "0"}, {"fixed": "13.0.1"}]}, False),
    ],
)
def test_version_matches_range(manager, version, rng, expected):
    assert version_matches_range(manager, version, rng) is expected


def test_prerelease_below_introduced_is_not_affected():
    rng = {"events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}
    assert version_matches_range("npm", "1.0.0-rc.1", rng) is False


def test_explicit_versions_list():
    affected = {"versions": ["1.2.3", "1.2.4"]}
    assert version_is_affected("pypi", "1.2.3", affected) is True
    assert version_is_affected("pypi", "1.2.5", affected) is False


def test_git_ranges_ignored():
    affected = {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}
    assert version_is_affected("go", "v1.0.0", affected) is False


def test_normalized_version_equivalence_pypi():
    affected = {"versions": ["2.0"]}
    assert version_is_affected("pypi", "2.0.0", affected) is True


# --------------------------------------------------------------------------- CVSS и находки
def test_cvss_v3_critical():
    score = cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == pytest.approx(9.8, abs=0.1)


def test_cvss_v3_low():
    score = cvss_v3_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert score is not None and score < 4.0


def test_cvss_invalid_vector():
    assert cvss_v3_score("nonsense") is None


OSV_RECORD = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["CVE-2024-1234"],
    "summary": "Уязвимость в парсере",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "references": [{"type": "ADVISORY", "url": "https://example.org/advisory"}],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "vulnpkg"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.3"}]}],
        }
    ],
}


def test_finding_from_osv_matches_and_scores():
    finding = finding_from_osv(OSV_RECORD, "pypi", "1.2.0")
    assert finding is not None
    assert finding.external_id == "GHSA-xxxx-yyyy-zzzz"
    assert finding.score == pytest.approx(98.0, abs=1.0)
    assert finding.fixed_versions == ["1.4.3"]
    assert finding.url == "https://example.org/advisory"


def test_finding_from_osv_skips_unaffected_version():
    assert finding_from_osv(OSV_RECORD, "pypi", "1.4.3") is None


def test_finding_from_osv_skips_other_ecosystem():
    assert finding_from_osv(OSV_RECORD, "npm", "1.2.0") is None


def test_finding_severity_fallback_without_cvss():
    record = {
        "id": "GHSA-1",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "p"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
            }
        ],
    }
    finding = finding_from_osv(record, "npm", "1.0.0")
    assert finding is not None
    assert finding.score == 75.0
