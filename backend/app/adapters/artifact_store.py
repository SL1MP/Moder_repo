"""Абстракция хранения пакетов в артефактори.

`NexusArtifactStore` — Sonatype Nexus 3 (один инстанс на все менеджеры: hosted-репозиторий
на каждый менеджер плюс raw-репозиторий со снапшотами OSV).
`GenericArtifactStore` — внешний Artifactory (JFrog и совместимые) по шаблонам путей.

Адаптер обязан уметь читать произвольный файл из репозитория — через это забирается
снапшот базы OSV.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

import httpx

from app.core.config import Settings, get_settings
from app.core.errors import UpstreamError
from app.core.http import client, request_with_retries
from app.core.logging import get_logger
from app.managers.base import PackageRef
from app.managers.registry import get_plugin
from app.managers.utils import parse_iso8601

log = get_logger(__name__)


@dataclass
class RemoteFile:
    path: str
    size_bytes: int | None = None
    checksum: str | None = None
    checksum_algo: str | None = None
    last_modified: datetime | None = None
    url: str | None = None


class ArtifactStore(ABC):
    """Контракт целевого артефактори."""

    @abstractmethod
    def publish(self, ref: PackageRef, filename: str, data: bytes) -> str:
        """Публикует артефакт в hosted-репозиторий менеджера. Возвращает URL. Идемпотентно."""

    @abstractmethod
    def artifact_url(self, ref: PackageRef, filename: str) -> str:
        """URL артефакта во внутреннем репозитории."""

    @abstractmethod
    def exists(self, ref: PackageRef, filename: str) -> bool:
        """Есть ли артефакт в репозитории (для идемпотентной публикации)."""

    @abstractmethod
    def delete(self, ref: PackageRef, filename: str) -> bool:
        """Снимает артефакт с публикации (отзыв пакета)."""

    @abstractmethod
    def read_file(self, repo: str, path: str) -> bytes:
        """Читает произвольный файл из репозитория (снапшот OSV)."""

    @abstractmethod
    def stat_file(self, repo: str, path: str) -> RemoteFile | None:
        """Метаданные файла: размер, хеш, дата — без скачивания тела."""

    @abstractmethod
    def download(self, url: str) -> bytes:
        """Скачивает файл по URL внутри артефактори (перепроверка одобренных)."""

    def ensure_repositories(self) -> list[str]:  # pragma: no cover - bootstrap
        """Создаёт нужные репозитории, если поддерживается. Возвращает созданные."""
        return []


class _HttpArtifactStore(ArtifactStore):
    service = "artifact-store"

    def __init__(self, settings: Settings | None = None) -> None:
        self.s = settings or get_settings()
        self.base = self.s.artifact_base_url.rstrip("/")

    def _auth_headers(self) -> dict[str, str]:
        return {}

    def _auth(self) -> tuple[str, str] | None:
        if self.s.artifact_user and self.s.artifact_token:
            return (self.s.artifact_user, self.s.artifact_token)
        return None

    def _get(self, url: str, **kwargs) -> httpx.Response:
        with client() as http:
            return request_with_retries(
                self.service,
                lambda: http.get(url, auth=self._auth(), headers=self._auth_headers(), **kwargs),
                retry_status={408, 429, 500, 502, 503, 504},
            )

    def download(self, url: str) -> bytes:
        resp = self._get(url)
        if resp.status_code >= 400:
            raise UpstreamError(
                f"Не удалось скачать файл из артефактори ({resp.status_code}): {url}",
                url=url,
                status=resp.status_code,
            )
        return resp.content

    def read_file(self, repo: str, path: str) -> bytes:
        return self.download(self.file_url(repo, path))

    @abstractmethod
    def file_url(self, repo: str, path: str) -> str: ...

    def stat_file(self, repo: str, path: str) -> RemoteFile | None:
        url = self.file_url(repo, path)
        with client() as http:
            resp = request_with_retries(
                self.service,
                lambda: http.head(url, auth=self._auth(), headers=self._auth_headers()),
                retry_status={408, 429, 500, 502, 503, 504},
            )
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise UpstreamError(
                f"Артефактори ответил {resp.status_code} на HEAD {url}", status=resp.status_code
            )
        size = resp.headers.get("content-length")
        checksum = resp.headers.get("x-checksum-sha256") or resp.headers.get("x-checksum-sha1")
        algo = "sha256" if resp.headers.get("x-checksum-sha256") else None
        if checksum and algo is None:
            algo = "sha1"
        etag = (resp.headers.get("etag") or "").strip('"{}')
        return RemoteFile(
            path=path,
            size_bytes=int(size) if size and size.isdigit() else None,
            checksum=checksum or (etag or None),
            checksum_algo=algo or ("etag" if etag else None),
            last_modified=parse_iso8601(resp.headers.get("x-artifactory-last-modified"))
            or _parse_http_date(resp.headers.get("last-modified")),
            url=url,
        )


def _parse_http_date(value: str | None) -> datetime | None:
    if not value:
        return None
    from email.utils import parsedate_to_datetime

    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None


class NexusArtifactStore(_HttpArtifactStore):
    """Sonatype Nexus 3 — один инстанс на все менеджеры, управление через REST API."""

    service = "nexus"

    def file_url(self, repo: str, path: str) -> str:
        return f"{self.base}/repository/{repo}/{path.lstrip('/')}"

    def artifact_url(self, ref: PackageRef, filename: str) -> str:
        repo = self.s.artifact_repo(ref.manager)
        return self.file_url(repo, self._asset_path(ref, filename))

    def _asset_path(self, ref: PackageRef, filename: str) -> str:
        if ref.manager == "pypi":
            return f"packages/{ref.name}/{ref.raw_version}/{filename}"
        if ref.manager == "npm":
            return f"{ref.display_name}/-/{filename}"
        if ref.manager == "go":
            return f"{get_plugin('go').publish_target(ref, filename)['directory']}/{filename}"
        return f"{ref.name}/{ref.version}/{filename}"

    def exists(self, ref: PackageRef, filename: str) -> bool:
        repo = self.s.artifact_repo(ref.manager)
        return self.stat_file(repo, self._asset_path(ref, filename)) is not None

    def publish(self, ref: PackageRef, filename: str, data: bytes) -> str:
        repo = self.s.artifact_repo(ref.manager)
        url = self.artifact_url(ref, filename)
        if self.exists(ref, filename):
            log.info("артефакт уже в Nexus, публикация не требуется", extra={"url": url})
            return url

        target = get_plugin(ref.manager).publish_target(ref, filename)
        upload = f"{self.base}/service/rest/v1/components?repository={repo}"
        if target["format"] == "raw":
            files = {"raw.asset1": (filename, data, "application/octet-stream")}
            payload = {"raw.directory": target["directory"], "raw.asset1.filename": filename}
        else:
            files = {target["asset_field"]: (filename, data, "application/octet-stream")}
            payload = {}

        with client() as http:
            resp = request_with_retries(
                self.service,
                lambda: http.post(upload, files=files, data=payload, auth=self._auth()),
                retry_status={408, 429, 500, 502, 503, 504},
            )
        if resp.status_code in (400, 409) and self.exists(ref, filename):
            return url  # уже опубликован параллельной задачей — идемпотентно
        if resp.status_code >= 400:
            raise UpstreamError(
                f"Nexus отклонил публикацию {filename} ({resp.status_code}): {resp.text[:300]}",
                status=resp.status_code,
                repo=repo,
            )
        return url

    def delete(self, ref: PackageRef, filename: str) -> bool:
        repo = self.s.artifact_repo(ref.manager)
        search = (
            f"{self.base}/service/rest/v1/search?repository={repo}"
            f"&name={ref.name}&version={ref.raw_version}"
        )
        resp = self._get(search)
        if resp.status_code >= 400:
            raise UpstreamError(f"Nexus ответил {resp.status_code} на поиск компонента")
        items = resp.json().get("items") or []
        deleted = False
        for item in items:
            component_id = item.get("id")
            if not component_id:
                continue
            with client() as http:
                del_resp = request_with_retries(
                    self.service,
                    lambda cid=component_id: http.delete(
                        f"{self.base}/service/rest/v1/components/{cid}", auth=self._auth()
                    ),
                    retry_status={408, 429, 500, 502, 503, 504},
                )
            deleted = deleted or del_resp.status_code in (204, 404)
        return deleted

    # ------------------------------------------------------------------ bootstrap
    def ensure_repositories(self) -> list[str]:  # pragma: no cover - требует Nexus
        created: list[str] = []
        recipes = [
            (self.s.artifact_repo_pypi, "pypi"),
            (self.s.artifact_repo_npm, "npm"),
            (self.s.artifact_repo_go, "raw"),
            (self.s.artifact_repo_nuget, "nuget"),
            (self.s.artifact_repo_osv, "raw"),
        ]
        for name, recipe in recipes:
            if not name:
                continue
            check = self._get(f"{self.base}/service/rest/v1/repositories/{recipe}/hosted/{name}")
            if check.status_code == 200:
                continue
            body = {
                "name": name,
                "online": True,
                "storage": {
                    "blobStoreName": "default",
                    "strictContentTypeValidation": recipe != "raw",
                    "writePolicy": "ALLOW",
                },
            }
            if recipe == "raw":
                body["raw"] = {"contentDisposition": "ATTACHMENT"}
            with client() as http:
                resp = request_with_retries(
                    self.service,
                    lambda b=body, r=recipe: http.post(
                        f"{self.base}/service/rest/v1/repositories/{r}/hosted",
                        json=b,
                        auth=self._auth(),
                    ),
                    retry_status={408, 429, 500, 502, 503, 504},
                )
            if resp.status_code < 400:
                created.append(name)
            else:
                log.warning(
                    "не удалось создать репозиторий Nexus",
                    extra={"repo": name, "status": resp.status_code, "body": resp.text[:200]},
                )
        return created


class GenericArtifactStore(_HttpArtifactStore):
    """Внешний Artifactory (JFrog или совместимый): PUT по шаблону пути."""

    service = "artifactory"

    def _auth_headers(self) -> dict[str, str]:
        if self.s.artifact_auth_type == "token" and self.s.artifact_token:
            return {"Authorization": f"Bearer {self.s.artifact_token}"}
        return {}

    def _auth(self) -> tuple[str, str] | None:
        if self.s.artifact_auth_type == "token":
            return None
        return super()._auth()

    def file_url(self, repo: str, path: str) -> str:
        return f"{self.base}/{repo}/{path.lstrip('/')}"

    def _path(self, ref: PackageRef, filename: str) -> str:
        template = self.s.artifact_path_template(ref.manager)
        return template.format(
            repo=self.s.artifact_repo(ref.manager),
            name=ref.display_name,
            normalized_name=ref.name,
            version=ref.raw_version,
            filename=filename,
        ).lstrip("/")

    def artifact_url(self, ref: PackageRef, filename: str) -> str:
        return f"{self.base}/{self._path(ref, filename)}"

    def exists(self, ref: PackageRef, filename: str) -> bool:
        path = self._path(ref, filename)
        repo, _, rest = path.partition("/")
        return self.stat_file(repo, rest) is not None

    def publish(self, ref: PackageRef, filename: str, data: bytes) -> str:
        url = self.artifact_url(ref, filename)
        if self.exists(ref, filename):
            return url
        headers = {
            **self._auth_headers(),
            "X-Checksum-Sha256": hashlib.sha256(data).hexdigest(),
            "Content-Type": "application/octet-stream",
        }
        with client() as http:
            resp = request_with_retries(
                self.service,
                lambda: http.put(url, content=data, headers=headers, auth=self._auth()),
                retry_status={408, 429, 500, 502, 503, 504},
            )
        if resp.status_code >= 400:
            raise UpstreamError(
                f"Artifactory отклонил публикацию {filename} ({resp.status_code}): {resp.text[:300]}",
                status=resp.status_code,
            )
        return url

    def delete(self, ref: PackageRef, filename: str) -> bool:
        url = self.artifact_url(ref, filename)
        with client() as http:
            resp = request_with_retries(
                self.service,
                lambda: http.delete(url, headers=self._auth_headers(), auth=self._auth()),
                retry_status={408, 429, 500, 502, 503, 504},
            )
        return resp.status_code in (200, 204, 404)


_store: ArtifactStore | None = None


def get_artifact_store() -> ArtifactStore:
    global _store
    if _store is None:
        s = get_settings()
        _store = NexusArtifactStore(s) if s.artifact_store == "nexus" else GenericArtifactStore(s)
    return _store


def set_artifact_store(store: ArtifactStore | None) -> None:
    """Подмена адаптера (тесты, bootstrap)."""
    global _store
    _store = store
