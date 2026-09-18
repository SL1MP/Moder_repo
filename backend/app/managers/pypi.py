"""Плагин менеджера pypi. Формат записи: `name==version`."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from app.core.config import get_settings
from app.core.errors import InvalidPackageFormat, UpstreamError
from app.core.http import client, request_with_retries
from app.managers.base import PackageManagerPlugin, PackageRef, ParsedEntry, RegistryMetadata
from app.managers.parsers.python_files import (
    parse_poetry_lock,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from app.managers.utils import parse_iso8601, raw_deps_to_entries
from app.services.spdx import normalize_spdx, spdx_from_classifiers

_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")


class PypiPlugin(PackageManagerPlugin):
    code = "pypi"
    title = "PyPI (Python)"
    entry_format = "name==version"
    dependency_files = ("requirements*.txt", "poetry.lock", "pyproject.toml")
    # Формат не различает прямые и транзитивные — см. golang.py.
    indeterminate_kind_files = ("poetry.lock",)

    # ------------------------------------------------------------------ нормализация
    def normalize_name(self, name: str) -> str:
        # PEP 503: регистр не важен, разделители эквивалентны
        return re.sub(r"[-_.]+", "-", name.strip()).lower()

    def normalize_version(self, version: str) -> str:
        from packaging.version import InvalidVersion, Version

        version = version.strip()
        try:
            return str(Version(version))
        except InvalidVersion:
            return version

    def split_entry(self, entry: str) -> tuple[str, str]:
        text = entry.strip()
        if "==" not in text:
            raise InvalidPackageFormat(
                f"«{text}» не соответствует формату pypi. Ожидается: name==version "
                "(например, requests==2.31.0)",
                expected_format=self.entry_format,
            )
        name, _, version = text.partition("==")
        return name.strip(), version.strip()

    def validate_name(self, name: str) -> None:
        super().validate_name(name)
        if not _NAME_RE.match(name):
            raise InvalidPackageFormat(
                f"Недопустимое имя пакета pypi: «{name}» (PEP 503: буквы, цифры, «-», «_», «.»)"
            )

    def validate_version(self, version: str) -> None:
        from packaging.version import InvalidVersion, Version

        super().validate_version(version)
        try:
            Version(version)
        except InvalidVersion as exc:
            raise InvalidPackageFormat(
                f"Версия «{version}» не соответствует PEP 440 (например, 2.31.0, 1.0.0rc1)"
            ) from exc

    # ------------------------------------------------------------------ файлы
    def parse_dependency_file(self, filename: str, content: bytes) -> list[ParsedEntry]:
        base = filename.rsplit("/", 1)[-1]
        if base == "poetry.lock":
            raw = parse_poetry_lock(content)
        elif base == "pyproject.toml":
            raw = parse_pyproject_toml(content)
        elif base.startswith("requirements") and base.endswith(".txt"):
            raw = parse_requirements_txt(content)
        else:
            raise InvalidPackageFormat(
                f"Файл «{base}» не поддерживается для pypi. Поддерживаются: "
                "requirements.txt, poetry.lock, pyproject.toml"
            )
        return raw_deps_to_entries(self, raw)

    # ------------------------------------------------------------------ реестр
    def fetch_metadata(self, ref: PackageRef) -> RegistryMetadata:
        base = get_settings().registry_pypi_url.rstrip("/")
        url = f"{base}/pypi/{ref.name}/{ref.raw_version}/json"
        with client() as http:
            resp = request_with_retries("pypi", lambda: http.get(url, headers={"Accept": "application/json"}))
        if resp.status_code == 404:
            raise UpstreamError(
                f"Пакет {ref.display_name}=={ref.raw_version} не найден в реестре pypi",
                registry="pypi",
            )
        if resp.status_code >= 400:
            raise UpstreamError(f"Реестр pypi ответил {resp.status_code}", registry="pypi")
        return self._parse_metadata(ref, resp.json())

    def _parse_metadata(self, ref: PackageRef, payload: dict[str, Any]) -> RegistryMetadata:
        info = payload.get("info") or {}
        urls = payload.get("urls") or []
        chosen = self._choose_dist(urls)

        published: datetime | None = None
        if chosen:
            published = parse_iso8601(chosen.get("upload_time_iso_8601") or chosen.get("upload_time"))
        if published is None:
            for entry in urls:
                published = parse_iso8601(entry.get("upload_time_iso_8601") or entry.get("upload_time"))
                if published:
                    break

        license_raw = (info.get("license") or "").strip() or None
        spdx = normalize_spdx(info.get("license_expression") or "") or normalize_spdx(license_raw or "")
        if not spdx:
            spdx = spdx_from_classifiers(info.get("classifiers") or [])

        digests = (chosen or {}).get("digests") or {}
        return RegistryMetadata(
            name=ref.name,
            version=ref.raw_version,
            published_at=published,
            license_spdx=spdx,
            license_raw=license_raw,
            artifact_url=(chosen or {}).get("url"),
            artifact_filename=(chosen or {}).get("filename"),
            checksum=digests.get("sha256"),
            checksum_algo="sha256" if digests.get("sha256") else None,
            size_bytes=(chosen or {}).get("size"),
            yanked=bool((chosen or {}).get("yanked") or info.get("yanked")),
            raw={"info": {k: info.get(k) for k in ("summary", "home_page", "project_urls")}},
        )

    @staticmethod
    def _choose_dist(urls: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Предпочитаем wheel: он же обычно и публикуется во внутренний репозиторий."""
        wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel"]
        if wheels:
            py3 = [u for u in wheels if "py3" in (u.get("python_version") or "")]
            return (py3 or wheels)[0]
        sdists = [u for u in urls if u.get("packagetype") == "sdist"]
        return (sdists or urls or [None])[0]

    # ------------------------------------------------------------------ публикация
    def publish_target(self, ref: PackageRef, filename: str) -> dict[str, str]:
        return {"format": "pypi", "filename": filename, "asset_field": "pypi.asset"}

    def install_command(self, ref: PackageRef, base_url: str, repo: str) -> str:
        index = f"{base_url.rstrip('/')}/repository/{repo}/simple"
        return f"pip install -i {index} {ref.display_name}=={ref.raw_version}"
