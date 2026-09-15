"""Формат записей пакетов и нормализация имён/версий по каждому менеджеру."""

from __future__ import annotations

import pytest

from app.core.errors import InvalidPackageFormat, UnknownManagerError
from app.managers.registry import detect_manager_by_file, get_plugin, manager_codes


def test_all_four_managers_registered():
    assert set(manager_codes()) == {"pypi", "npm", "go", "nuget"}


def test_unknown_manager():
    with pytest.raises(UnknownManagerError):
        get_plugin("cargo")


@pytest.mark.parametrize(
    ("manager", "entry", "name", "version"),
    [
        ("pypi", "requests==2.31.0", "requests", "2.31.0"),
        ("pypi", "Flask-SQLAlchemy==3.1.1", "flask-sqlalchemy", "3.1.1"),
        ("pypi", "zope.interface==6.1", "zope-interface", "6.1"),
        ("npm", "lodash@4.17.21", "lodash", "4.17.21"),
        ("npm", "@babel/core@7.24.0", "@babel/core", "7.24.0"),
        ("go", "github.com/gin-gonic/gin@v1.9.1", "github.com/gin-gonic/gin", "v1.9.1"),
        ("nuget", "Newtonsoft.Json@13.0.3", "newtonsoft.json", "13.0.3"),
    ],
)
def test_parse_entry(manager, entry, name, version):
    ref = get_plugin(manager).parse_entry(entry)
    assert ref.name == name
    assert ref.version == version
    assert ref.manager == manager


def test_pypi_normalizes_name_per_pep503():
    plugin = get_plugin("pypi")
    assert plugin.normalize_name("Zope.Interface") == "zope-interface"
    assert plugin.normalize_name("my_package") == "my-package"
    assert plugin.normalize_name("A--B") == "a-b"


def test_go_adds_v_prefix():
    ref = get_plugin("go").parse_entry("example.com/mod@1.2.3")
    assert ref.version == "v1.2.3"


def test_npm_scoped_display_name_kept():
    ref = get_plugin("npm").parse_entry("@Scope/Pkg@1.0.0")
    assert ref.display_name == "@Scope/Pkg"
    assert ref.name == "@scope/pkg"


@pytest.mark.parametrize(
    ("manager", "entry"),
    [
        ("pypi", "requests"),
        ("pypi", "requests>=2.0"),
        ("pypi", "requests==не-версия!"),
        ("npm", "lodash"),
        ("npm", "lodash@latest"),
        ("go", "github.com/x/y"),
        ("go", "github.com/x/y@master"),
        ("nuget", "Newtonsoft.Json"),
        ("nuget", "Newtonsoft.Json@v13"),
    ],
)
def test_invalid_format_reports_expected(manager, entry):
    plugin = get_plugin(manager)
    parsed = plugin.try_parse_entry(entry)
    assert parsed.ref is None
    assert parsed.expected_format == plugin.entry_format
    assert parsed.error


def test_make_ref_requires_version():
    with pytest.raises(InvalidPackageFormat, match="Не указана версия"):
        get_plugin("pypi").make_ref("requests", "")


@pytest.mark.parametrize(
    ("filename", "manager"),
    [
        ("requirements.txt", "pypi"),
        ("requirements-dev.txt", "pypi"),
        ("poetry.lock", "pypi"),
        ("pyproject.toml", "pypi"),
        ("package-lock.json", "npm"),
        ("yarn.lock", "npm"),
        ("go.mod", "go"),
        ("go.sum", "go"),
        ("packages.lock.json", "nuget"),
        ("packages.config", "nuget"),
        ("Api.csproj", "nuget"),
        ("Cargo.toml", None),
    ],
)
def test_detect_manager_by_file(filename, manager):
    assert detect_manager_by_file(filename) == manager


def test_install_commands_use_internal_repo():
    base = "http://nexus:8081"
    assert get_plugin("pypi").install_command(
        get_plugin("pypi").parse_entry("requests==2.31.0"), base, "pypi-internal"
    ) == "pip install -i http://nexus:8081/repository/pypi-internal/simple requests==2.31.0"
    assert "npm i --registry=" in get_plugin("npm").install_command(
        get_plugin("npm").parse_entry("lodash@4.17.21"), base, "npm-internal"
    )
    assert "GOPROXY=" in get_plugin("go").install_command(
        get_plugin("go").parse_entry("example.com/m@v1.0.0"), base, "go-internal"
    )
    assert "dotnet nuget add source" in get_plugin("nuget").install_command(
        get_plugin("nuget").parse_entry("Newtonsoft.Json@13.0.3"), base, "nuget-internal"
    )
