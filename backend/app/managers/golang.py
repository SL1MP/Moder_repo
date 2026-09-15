"""Плагин менеджера go. Формат записи: `module@vX.Y.Z`."""

from __future__ import annotations

import re
from typing import Any

from app.core.config import get_settings
from app.core.errors import InvalidPackageFormat, UpstreamError
from app.core.http import client, request_with_retries
from app.managers.base import PackageManagerPlugin, PackageRef, ParsedEntry, RegistryMetadata
from app.managers.parsers.go_files import parse_go_mod, parse_go_sum
from app.managers.utils import parse_iso8601, raw_deps_to_entries
from app.managers.versioning import compare_go

_MODULE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~\-]*(?:\.[A-Za-z0-9._~\-]+)*(?:/[A-Za-z0-9._~\-]+)*$")
_VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+incompatible)?$")


class GoPlugin(PackageManagerPlugin):
    code = "go"
    title = "Go modules"
    entry_format = "module@vX.Y.Z"
    dependency_files = ("go.mod", "go.sum")
    # go.sum перечисляет весь граф модулей и не отмечает, какие из них прямые.
    indeterminate_kind_files = ("go.sum",)

    def normalize_name(self, name: str) -> str:
        # Go module proxy требует escaping заглавных букв, но в базе храним как есть,
        # приводя к нижнему регистру только для уникальности сравнения.
        return name.strip().lower()

    def display_name(self, name: str) -> str:
        return name.strip()

    def normalize_version(self, version: str) -> str:
        version = version.strip()
        return version if version.startswith("v") else f"v{version}"

    def split_entry(self, entry: str) -> tuple[str, str]:
        text = entry.strip()
        if "@" not in text:
            raise InvalidPackageFormat(
                f"«{text}» не соответствует формату go. Ожидается: module@vX.Y.Z "
                "(например, github.com/gin-gonic/gin@v1.9.1)",
                expected_format=self.entry_format,
            )
        name, _, version = text.rpartition("@")
        return name.strip(), version.strip()

    def validate_name(self, name: str) -> None:
        super().validate_name(name)
        if not _MODULE_RE.match(name):
            raise InvalidPackageFormat(f"Недопустимый путь модуля go: «{name}»")

    def validate_version(self, version: str) -> None:
        super().validate_version(version)
        candidate = version if version.startswith("v") else f"v{version}"
        if not _VERSION_RE.match(candidate):
            raise InvalidPackageFormat(
                f"Версия «{version}» не соответствует формату go (например, v1.9.1, "
                "v0.0.0-20240101120000-abcdef123456)"
            )

    def compare_versions(self, a: str, b: str) -> int:
        return compare_go(a, b)

    # ------------------------------------------------------------------ файлы
    def parse_dependency_file(self, filename: str, content: bytes) -> list[ParsedEntry]:
        base = filename.rsplit("/", 1)[-1]
        if base == "go.mod":
            raw = parse_go_mod(content)
        elif base == "go.sum":
            raw = parse_go_sum(content)
        else:
            raise InvalidPackageFormat(
                f"Файл «{base}» не поддерживается для go. Поддерживаются: go.mod, go.sum"
            )
        return raw_deps_to_entries(self, raw)

    # ------------------------------------------------------------------ реестр
    @staticmethod
    def escape_module(path: str) -> str:
        """Go module proxy: заглавные буквы кодируются как `!x` (module path escaping)."""
        return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)

    def fetch_metadata(self, ref: PackageRef) -> RegistryMetadata:
        base = get_settings().registry_go_proxy.rstrip("/")
        module = self.escape_module(ref.display_name)
        version = self.escape_module(ref.version)
        info_url = f"{base}/{module}/@v/{version}.info"
        with client() as http:
            resp = request_with_retries("go", lambda: http.get(info_url))
            if resp.status_code == 404 or resp.status_code == 410:
                raise UpstreamError(
                    f"Модуль {ref.display_name}@{ref.version} не найден в go module proxy",
                    registry="go",
                )
            if resp.status_code >= 400:
                raise UpstreamError(f"Go module proxy ответил {resp.status_code}", registry="go")
            info: dict[str, Any] = resp.json()
            checksum = None
            hash_resp = http.get(f"{base}/{module}/@v/{version}.ziphash")
            if hash_resp.status_code == 200 and hash_resp.text.strip():
                checksum = hash_resp.text.strip()

        return RegistryMetadata(
            name=ref.name,
            version=ref.version,
            published_at=parse_iso8601(info.get("Time")),
            # Go module proxy не отдаёт лицензию — она определяется юристами (шаг 3)
            license_spdx=None,
            license_raw=None,
            artifact_url=f"{base}/{module}/@v/{version}.zip",
            artifact_filename=f"{ref.version}.zip",
            checksum=checksum,
            checksum_algo="h1" if checksum else None,
            raw={"origin": info.get("Origin")} if info.get("Origin") else {},
        )

    # ------------------------------------------------------------------ публикация
    def publish_target(self, ref: PackageRef, filename: str) -> dict[str, str]:
        # Nexus хранит go-модули в raw-репозитории по схеме GOPROXY.
        return {
            "format": "raw",
            "filename": filename,
            "directory": f"{self.escape_module(ref.display_name)}/@v",
        }

    def install_command(self, ref: PackageRef, base_url: str, repo: str) -> str:
        proxy = f"{base_url.rstrip('/')}/repository/{repo}"
        return f"GOPROXY={proxy} GONOSUMDB=* GONOSUMCHECK=1 go get {ref.display_name}@{ref.version}"
