"""Плагин менеджера nuget. Формат записи: `Id@version`."""

from __future__ import annotations

import re
from typing import Any

from app.core.config import get_settings
from app.core.errors import InvalidPackageFormat, UpstreamError
from app.core.http import client, request_with_retries
from app.managers.base import PackageManagerPlugin, PackageRef, ParsedEntry, RegistryMetadata
from app.managers.parsers.dotnet_files import (
    parse_csproj,
    parse_packages_config,
    parse_packages_lock_json,
)
from app.managers.utils import parse_iso8601, raw_deps_to_entries
from app.managers.versioning import compare_nuget
from app.services.spdx import normalize_spdx

_ID_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?$")
_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")


class NugetPlugin(PackageManagerPlugin):
    code = "nuget"
    title = "NuGet (.NET)"
    entry_format = "Id@version"
    dependency_files = ("packages.lock.json", "packages.config", "*.csproj")

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def normalize_version(self, version: str) -> str:
        return version.strip().lower()

    def split_entry(self, entry: str) -> tuple[str, str]:
        text = entry.strip()
        if "@" not in text:
            raise InvalidPackageFormat(
                f"«{text}» не соответствует формату nuget. Ожидается: Id@version "
                "(например, Newtonsoft.Json@13.0.3)",
                expected_format=self.entry_format,
            )
        name, _, version = text.rpartition("@")
        return name.strip(), version.strip()

    def validate_name(self, name: str) -> None:
        super().validate_name(name)
        if not _ID_RE.match(name):
            raise InvalidPackageFormat(
                f"Недопустимый Id пакета nuget: «{name}» (буквы, цифры, «.», «-», «_»)"
            )

    def validate_version(self, version: str) -> None:
        super().validate_version(version)
        if not _VERSION_RE.match(version):
            raise InvalidPackageFormat(
                f"Версия «{version}» не соответствует формату nuget (например, 13.0.3, 6.0.0-preview.5)"
            )

    def compare_versions(self, a: str, b: str) -> int:
        return compare_nuget(a, b)

    # ------------------------------------------------------------------ файлы
    def parse_dependency_file(self, filename: str, content: bytes) -> list[ParsedEntry]:
        base = filename.rsplit("/", 1)[-1]
        if base == "packages.lock.json":
            raw = parse_packages_lock_json(content)
        elif base == "packages.config":
            raw = parse_packages_config(content)
        elif base.endswith(".csproj"):
            raw = parse_csproj(content)
        else:
            raise InvalidPackageFormat(
                f"Файл «{base}» не поддерживается для nuget. Поддерживаются: "
                "packages.lock.json, packages.config, *.csproj"
            )
        return raw_deps_to_entries(self, raw)

    # ------------------------------------------------------------------ реестр
    def fetch_metadata(self, ref: PackageRef) -> RegistryMetadata:
        base = get_settings().registry_nuget_url.rstrip("/")
        pid, version = ref.name, ref.version
        url = f"{base}/v3/registration5-semver1/{pid}/{version}.json"
        with client() as http:
            resp = request_with_retries("nuget", lambda: http.get(url))
            if resp.status_code == 404:
                raise UpstreamError(
                    f"Пакет {ref.display_name}@{ref.raw_version} не найден в реестре nuget",
                    registry="nuget",
                )
            if resp.status_code >= 400:
                raise UpstreamError(f"Реестр nuget ответил {resp.status_code}", registry="nuget")
            payload: dict[str, Any] = resp.json()
        return self._parse_metadata(ref, payload, base)

    def _parse_metadata(self, ref: PackageRef, payload: dict[str, Any], base: str) -> RegistryMetadata:
        entry = payload.get("catalogEntry")
        if isinstance(entry, str):  # ссылка на каталог вместо inline-объекта
            with client() as http:
                resp = request_with_retries("nuget", lambda: http.get(entry))
            entry = resp.json() if resp.status_code < 400 else {}
        entry = entry or payload

        pid, version = ref.name, ref.version
        content_url = payload.get("packageContent") or entry.get("packageContent")
        if not content_url:
            content_url = f"{base}/v3-flatcontainer/{pid}/{version}/{pid}.{version}.nupkg"
        license_expr = entry.get("licenseExpression") or None
        return RegistryMetadata(
            name=ref.name,
            version=ref.version,
            published_at=parse_iso8601(entry.get("published")),
            license_spdx=normalize_spdx(license_expr),
            license_raw=license_expr or entry.get("licenseUrl"),
            artifact_url=content_url,
            artifact_filename=f"{pid}.{version}.nupkg",
            # NuGet отдаёт хеш только внутри .nupkg-манифеста; sha512 берётся из v3-flatcontainer
            checksum=None,
            checksum_algo=None,
            yanked=bool(entry.get("listed") is False),
            raw={"licenseUrl": entry.get("licenseUrl")} if entry.get("licenseUrl") else {},
        )

    # ------------------------------------------------------------------ публикация
    def publish_target(self, ref: PackageRef, filename: str) -> dict[str, str]:
        return {"format": "nuget", "filename": filename, "asset_field": "nuget.asset"}

    def install_command(self, ref: PackageRef, base_url: str, repo: str) -> str:
        source = f"{base_url.rstrip('/')}/repository/{repo}/index.json"
        return (
            f"dotnet nuget add source {source} -n internal && "
            f"dotnet add package {ref.display_name} -v {ref.raw_version} -s {source}"
        )
