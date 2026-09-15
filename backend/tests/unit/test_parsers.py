"""Парсеры файлов зависимостей: прямые/транзитивные и ошибки формата."""

from __future__ import annotations

import pytest

from app.core.errors import InvalidPackageFormat
from app.managers.registry import parse_file

REQUIREMENTS = b"""
# comment
requests==2.31.0
pydantic==2.6.4  # inline comment
Flask-SQLAlchemy==3.1.1
urllib3>=2.0            ; not pinned
-r other.txt
--index-url https://example.org/simple
httpx[http2]==0.27.0
"""

POETRY_LOCK = b"""
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "certifi"
version = "2024.2.2"
"""

PYPROJECT = b"""
[project]
name = "svc"
dependencies = ["requests==2.31.0", "pydantic>=2.0"]

[tool.poetry.dependencies]
python = "^3.12"
httpx = "0.27.0"
uvicorn = "^0.30"
"""

PACKAGE_LOCK_V3 = b"""
{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"lodash": "^4.17.21"}, "devDependencies": {"vite": "^5.0.0"}},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/vite": {"version": "5.2.0"},
    "node_modules/nanoid": {"version": "3.3.7"},
    "node_modules/link": {"link": true, "resolved": "../x"}
  }
}
"""

PACKAGE_LOCK_V1 = b"""
{
  "name": "app",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {"version": "4.17.21", "dependencies": {"inner": {"version": "1.0.0"}}}
  },
  "devDependencies": {}
}
"""

YARN_LOCK = b"""
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@babel/core@^7.24.0":
  version "7.24.0"
"""

GO_MOD = b"""
module example.com/svc

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/sys v0.18.0 // indirect
)

require github.com/stretchr/testify v1.9.0
"""

GO_SUM = b"""
github.com/gin-gonic/gin v1.9.1 h1:abc=
github.com/gin-gonic/gin v1.9.1/go.mod h1:def=
golang.org/x/sys v0.18.0 h1:xyz=
"""

PACKAGES_LOCK = b"""
{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3"},
      "System.Text.Json": {"type": "Transitive", "resolved": "8.0.3"},
      "MyLib": {"type": "Project"}
    }
  }
}
"""

PACKAGES_CONFIG = b"""<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="Serilog" version="3.1.1" targetFramework="net48" />
</packages>
"""

CSPROJ = b"""<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog" Version="$(SerilogVersion)" />
    <PackageReference Include="Dapper"><Version>2.1.35</Version></PackageReference>
  </ItemGroup>
</Project>
"""


def _by_name(entries):
    return {e.ref.name: e.ref for e in entries if e.ref}


def test_requirements_txt_pins_only():
    entries = parse_file("pypi", "requirements.txt", REQUIREMENTS)
    refs = _by_name(entries)
    assert refs["requests"].version == "2.31.0"
    assert refs["flask-sqlalchemy"].version == "3.1.1"
    assert refs["httpx"].version == "0.27.0"
    errors = [e for e in entries if e.ref is None]
    assert any("urllib3" in (e.error or "") for e in errors)


def test_requirements_all_direct():
    entries = parse_file("pypi", "requirements.txt", b"requests==2.31.0\n")
    assert entries[0].ref.dependency_kind == "direct"


def test_poetry_lock_is_transitive():
    entries = parse_file("pypi", "poetry.lock", POETRY_LOCK)
    assert {e.ref.name for e in entries} == {"requests", "certifi"}
    assert all(e.ref.dependency_kind == "transitive" for e in entries)


def test_pyproject_direct_and_ranges():
    entries = parse_file("pypi", "pyproject.toml", PYPROJECT)
    refs = _by_name(entries)
    assert refs["requests"].version == "2.31.0"
    assert refs["httpx"].version == "0.27.0"
    unresolved = [e.error for e in entries if e.ref is None]
    assert any("pydantic" in (e or "") for e in unresolved)
    assert any("uvicorn" in (e or "") for e in unresolved)


def test_package_lock_v3_direct_vs_transitive():
    entries = parse_file("npm", "package-lock.json", PACKAGE_LOCK_V3)
    kinds = {e.ref.name: e.ref.dependency_kind for e in entries if e.ref}
    assert kinds["lodash"] == "direct"
    assert kinds["vite"] == "direct"
    assert kinds["nanoid"] == "transitive"
    assert "link" not in kinds


def test_package_lock_v1():
    entries = parse_file("npm", "package-lock.json", PACKAGE_LOCK_V1)
    kinds = {e.ref.name: e.ref.dependency_kind for e in entries if e.ref}
    assert kinds["lodash"] == "direct"
    assert kinds["inner"] == "transitive"


def test_yarn_lock_scoped():
    entries = parse_file("npm", "yarn.lock", YARN_LOCK)
    refs = _by_name(entries)
    assert refs["lodash"].version == "4.17.21"
    assert refs["@babel/core"].version == "7.24.0"


def test_go_mod_indirect_is_transitive():
    entries = parse_file("go", "go.mod", GO_MOD)
    kinds = {e.ref.name: e.ref.dependency_kind for e in entries if e.ref}
    assert kinds["github.com/gin-gonic/gin"] == "direct"
    assert kinds["golang.org/x/sys"] == "transitive"
    assert kinds["github.com/stretchr/testify"] == "direct"


def test_go_sum_strips_gomod_suffix():
    entries = parse_file("go", "go.sum", GO_SUM)
    refs = {(e.ref.name, e.ref.version) for e in entries if e.ref}
    assert ("github.com/gin-gonic/gin", "v1.9.1") in refs
    assert len(refs) == 2


def test_packages_lock_json_kinds():
    entries = parse_file("nuget", "packages.lock.json", PACKAGES_LOCK)
    kinds = {e.ref.name: e.ref.dependency_kind for e in entries if e.ref}
    assert kinds["newtonsoft.json"] == "direct"
    assert kinds["system.text.json"] == "transitive"
    assert "mylib" not in kinds


def test_packages_config():
    entries = parse_file("nuget", "packages.config", PACKAGES_CONFIG)
    refs = _by_name(entries)
    assert refs["newtonsoft.json"].version == "13.0.3"
    assert refs["serilog"].version == "3.1.1"


def test_csproj_variable_version_reported():
    entries = parse_file("nuget", "App.csproj", CSPROJ)
    refs = _by_name(entries)
    assert refs["newtonsoft.json"].version == "13.0.3"
    assert refs["dapper"].version == "2.1.35"
    assert any("Serilog" in (e.error or "") for e in entries if e.ref is None)


def test_file_not_supported_by_manager():
    with pytest.raises(InvalidPackageFormat, match="не поддерживается"):
        parse_file("pypi", "package-lock.json", b"{}")


def test_broken_json_reports_format_error():
    with pytest.raises(InvalidPackageFormat, match="не является корректным JSON"):
        parse_file("npm", "package-lock.json", b"{ broken")


def test_broken_xml_reports_format_error():
    with pytest.raises(InvalidPackageFormat, match="не является корректным XML"):
        parse_file("nuget", "packages.config", b"<packages>")


def test_go_sum_entries_are_not_dropped_as_transitive():
    """go.sum не различает прямые и транзитивные — помечать всё транзитивным нельзя.

    Пометка «transitive» отбрасывалась фильтром при include_transitive=false,
    и заявка из go.sum получалась пустой: снаружи выглядело как «go.sum не
    поддерживается».
    """
    entries = parse_file("go", "go.sum", GO_SUM)
    kinds = {e.ref.dependency_kind for e in entries if e.ref}

    assert entries, "go.sum должен разбираться"
    assert kinds == {"direct"}
