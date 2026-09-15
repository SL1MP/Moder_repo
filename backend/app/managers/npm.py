"""Плагин менеджера npm. Формат записи: `[@scope/]name@version`."""

from __future__ import annotations

import base64
import re
from typing import Any

from app.core.config import get_settings
from app.core.errors import InvalidPackageFormat, UpstreamError
from app.core.http import client, request_with_retries
from app.managers.base import PackageManagerPlugin, PackageRef, ParsedEntry, RegistryMetadata
from app.managers.parsers.js_files import parse_package_json, parse_package_lock, parse_yarn_lock
from app.managers.utils import parse_iso8601, raw_deps_to_entries
from app.managers.versioning import compare_semver
from app.services.spdx import normalize_spdx

_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._\-]*/)?[a-z0-9][a-z0-9._\-]*$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")


class NpmPlugin(PackageManagerPlugin):
    code = "npm"
    title = "npm (Node.js)"
    entry_format = "[@scope/]name@version"
    dependency_files = ("package-lock.json", "yarn.lock", "package.json")

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def split_entry(self, entry: str) -> tuple[str, str]:
        text = entry.strip()
        scoped = text.startswith("@")
        body = text[1:] if scoped else text
        if "@" not in body:
            raise InvalidPackageFormat(
                f"«{text}» не соответствует формату npm. Ожидается: [@scope/]name@version "
                "(например, lodash@4.17.21 или @babel/core@7.24.0)",
                expected_format=self.entry_format,
            )
        name, _, version = body.partition("@")
        return (("@" + name) if scoped else name), version.strip()

    def validate_name(self, name: str) -> None:
        super().validate_name(name)
        if not _NAME_RE.match(name.lower()):
            raise InvalidPackageFormat(
                f"Недопустимое имя пакета npm: «{name}» (строчные буквы, цифры, «-», «_», «.», "
                "опциональный @scope/)"
            )

    def validate_version(self, version: str) -> None:
        super().validate_version(version)
        if not _VERSION_RE.match(version):
            raise InvalidPackageFormat(
                f"Версия «{version}» не соответствует semver (например, 4.17.21, 7.0.0-rc.1)"
            )

    def compare_versions(self, a: str, b: str) -> int:
        return compare_semver(a, b)

    # ------------------------------------------------------------------ файлы
    def parse_dependency_file(self, filename: str, content: bytes) -> list[ParsedEntry]:
        base = filename.rsplit("/", 1)[-1]
        if base == "package-lock.json":
            raw = parse_package_lock(content)
        elif base == "yarn.lock":
            raw = parse_yarn_lock(content)
        elif base == "package.json":
            raw = parse_package_json(content)
        else:
            raise InvalidPackageFormat(
                f"Файл «{base}» не поддерживается для npm. Поддерживаются: "
                "package-lock.json, yarn.lock, package.json"
            )
        return raw_deps_to_entries(self, raw)

    # ------------------------------------------------------------------ реестр
    def fetch_metadata(self, ref: PackageRef) -> RegistryMetadata:
        base = get_settings().registry_npm_url.rstrip("/")
        url = f"{base}/{ref.name.replace('/', '%2f')}"
        with client() as http:
            resp = request_with_retries(
                "npm",
                lambda: http.get(url, headers={"Accept": "application/vnd.npm.install-v1+json, */*"}),
            )
        if resp.status_code == 404:
            raise UpstreamError(
                f"Пакет {ref.display_name}@{ref.raw_version} не найден в реестре npm", registry="npm"
            )
        if resp.status_code >= 400:
            raise UpstreamError(f"Реестр npm ответил {resp.status_code}", registry="npm")
        return self._parse_metadata(ref, resp.json())

    def _parse_metadata(self, ref: PackageRef, payload: dict[str, Any]) -> RegistryMetadata:
        versions = payload.get("versions") or {}
        meta = versions.get(ref.raw_version)
        if meta is None:
            raise UpstreamError(
                f"Версия {ref.raw_version} пакета {ref.display_name} отсутствует в реестре npm",
                registry="npm",
                available=len(versions),
            )
        published = parse_iso8601((payload.get("time") or {}).get(ref.raw_version))
        dist = meta.get("dist") or {}
        checksum, algo = self._checksum(dist)
        license_value = meta.get("license") or payload.get("license")
        if isinstance(license_value, dict):
            license_value = license_value.get("type")
        tarball = dist.get("tarball")
        filename = tarball.rsplit("/", 1)[-1] if tarball else None
        deprecated = meta.get("deprecated")
        return RegistryMetadata(
            name=ref.name,
            version=ref.raw_version,
            published_at=published,
            license_spdx=normalize_spdx(license_value if isinstance(license_value, str) else None),
            license_raw=license_value if isinstance(license_value, str) else None,
            artifact_url=tarball,
            artifact_filename=filename,
            checksum=checksum,
            checksum_algo=algo,
            size_bytes=dist.get("unpackedSize"),
            yanked=bool(deprecated),
            raw={"deprecated": deprecated} if deprecated else {},
        )

    @staticmethod
    def _checksum(dist: dict[str, Any]) -> tuple[str | None, str | None]:
        """`integrity` (sha512 в base64) предпочтительнее устаревшего `shasum` (sha1)."""
        integrity = dist.get("integrity")
        if isinstance(integrity, str) and "-" in integrity:
            algo, _, b64 = integrity.partition("-")
            try:
                return base64.b64decode(b64).hex(), algo
            except (ValueError, TypeError):
                pass
        shasum = dist.get("shasum")
        return (shasum, "sha1") if shasum else (None, None)

    # ------------------------------------------------------------------ публикация
    def publish_target(self, ref: PackageRef, filename: str) -> dict[str, str]:
        return {"format": "npm", "filename": filename, "asset_field": "npm.asset"}

    def install_command(self, ref: PackageRef, base_url: str, repo: str) -> str:
        registry = f"{base_url.rstrip('/')}/repository/{repo}/"
        return f"npm i --registry={registry} {ref.display_name}@{ref.raw_version}"
