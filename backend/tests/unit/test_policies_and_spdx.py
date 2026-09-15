"""Blacklist, справочник лицензий и нормализация SPDX."""

from __future__ import annotations

import textwrap

import pytest

from app.services.policies import (
    _version_in_spec,
    load_blacklist,
    load_license_policy,
    reload_policies,
)
from app.services.spdx import normalize_spdx, spdx_from_classifiers


# --------------------------------------------------------------------------- диапазоны версий
@pytest.mark.parametrize(
    ("manager", "version", "spec", "expected"),
    [
        ("pypi", "1.0.0", "*", True),
        ("pypi", "1.0.0", "==1.0.0", True),
        ("pypi", "1.0.1", "==1.0.0", False),
        ("pypi", "1.5.0", ">=1.0,<2.0", True),
        ("pypi", "2.0.0", ">=1.0,<2.0", False),
        ("npm", "3.3.6", "==3.3.6", True),
        ("npm", "4.0.0", ">=3.0.0", True),
        ("go", "v1.2.0", ">=v1.0.0,<v2.0.0", True),
        ("nuget", "13.0.3", "13.0.3", True),
        ("pypi", "1.0.0", "!=1.0.0", False),
    ],
)
def test_version_in_spec(manager, version, spec, expected):
    assert _version_in_spec(manager, version, spec) is expected


# --------------------------------------------------------------------------- blacklist
BLACKLIST_YML = textwrap.dedent(
    """
    rules:
      - manager: pypi
        name: colourama
        versions: "*"
        reason: Тайпсквоттинг
      - name: "internal-*"
        versions: "*"
        reason: Dependency confusion
      - manager: npm
        name: event-stream
        versions: "==3.3.6"
        reason: Бэкдор
      - name: ""
    """
)


def test_load_blacklist(tmp_path):
    path = tmp_path / "blacklist.yml"
    path.write_text(BLACKLIST_YML, "utf-8")
    bl = load_blacklist(str(path))
    assert len(bl.rules) == 3  # правило без имени пропущено
    assert bl.find("pypi", "colourama", "0.1.0") is not None
    assert bl.find("npm", "colourama", "0.1.0") is None  # правило только для pypi
    assert bl.find("nuget", "internal-tools", "1.0.0") is not None  # любой менеджер
    assert bl.find("npm", "event-stream", "3.3.6") is not None
    assert bl.find("npm", "event-stream", "4.0.0") is None


def test_missing_blacklist_file_is_reported_not_fatal(tmp_path):
    bl = load_blacklist(str(tmp_path / "missing.yml"))
    assert bl.rules == []
    assert bl.error


def test_broken_yaml_is_reported(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("- just: a list\n", "utf-8")
    bl = load_blacklist(str(path))
    assert bl.error


# --------------------------------------------------------------------------- лицензии
LICENSES_YML = textwrap.dedent(
    """
    allowed:
      - spdx_id: MIT
        name: MIT License
      - Apache-2.0
    forbidden:
      - spdx_id: AGPL-3.0-only
    """
)


def test_load_license_policy(tmp_path):
    path = tmp_path / "licenses.yml"
    path.write_text(LICENSES_YML, "utf-8")
    policy = load_license_policy(str(path))
    assert policy.is_allowed("MIT")
    assert policy.is_allowed("apache-2.0")
    assert not policy.is_allowed("AGPL-3.0-only")
    assert not policy.is_allowed(None)
    assert not policy.is_allowed("GPL-3.0-only")
    assert policy.known_ids() == ["Apache-2.0", "MIT"]


def test_composite_expressions(tmp_path):
    path = tmp_path / "licenses.yml"
    path.write_text(LICENSES_YML, "utf-8")
    policy = load_license_policy(str(path))
    assert policy.is_allowed("MIT OR AGPL-3.0-only")  # достаточно одной разрешённой
    assert not policy.is_allowed("MIT AND AGPL-3.0-only")


def test_reload_policies_reports_state(tmp_path, monkeypatch):
    bl = tmp_path / "blacklist.yml"
    lic = tmp_path / "licenses.yml"
    bl.write_text(BLACKLIST_YML, "utf-8")
    lic.write_text(LICENSES_YML, "utf-8")
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "blacklist_file", str(bl))
    monkeypatch.setattr(get_settings(), "allowed_licenses_file", str(lic))

    result = reload_policies()
    assert result["blacklist"]["rules"] == 3
    assert result["licenses"]["allowed"] == 2
    assert result["licenses"]["forbidden"] == 1


# --------------------------------------------------------------------------- SPDX
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("MIT", "MIT"),
        ("mit license", "MIT"),
        ("Apache License 2.0", "Apache-2.0"),
        ("Apache Software License", "Apache-2.0"),
        ("BSD License", "BSD-3-Clause"),
        ("ISC", "ISC"),
        ("MIT OR Apache-2.0", "MIT OR Apache-2.0"),
        ("UNKNOWN", None),
        ("", None),
        (None, None),
        ("Copyright (c) 2024 Somebody. Permission is hereby granted, free of charge, " * 5, None),
    ],
)
def test_normalize_spdx(value, expected):
    assert normalize_spdx(value) == expected


def test_spdx_from_classifiers():
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
    ]
    assert spdx_from_classifiers(classifiers) == "Apache-2.0"


def test_spdx_from_classifiers_none():
    assert spdx_from_classifiers(["Framework :: Django"]) is None
