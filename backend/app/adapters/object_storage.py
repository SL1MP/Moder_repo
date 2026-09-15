"""Временное хранилище артефактов (MinIO/S3).

MinIO — карантинная зона, а не архив: объект удаляется сразу после успешной выгрузки
в артефактори и сразу при отклонении пакета.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

from app.core.config import get_settings
from app.core.errors import UpstreamError
from app.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class StoredObject:
    bucket: str
    key: str
    size_bytes: int
    last_modified: datetime | None = None


class ObjectStorage(ABC):
    @abstractmethod
    def ensure_bucket(self) -> None: ...

    @abstractmethod
    def put(
        self, key: str, data: bytes, *, content_type: str = "application/octet-stream"
    ) -> StoredObject: ...

    @abstractmethod
    def get(self, key: str) -> bytes: ...

    @abstractmethod
    def delete(self, key: str) -> bool: ...

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def list_objects(self, prefix: str = "") -> list[StoredObject]: ...

    @property
    @abstractmethod
    def bucket(self) -> str: ...


class S3ObjectStorage(ObjectStorage):
    def __init__(self) -> None:
        self.s = get_settings()
        self._client = None

    @property
    def bucket(self) -> str:
        return self.s.s3_bucket

    def _c(self):
        if self._client is None:  # pragma: no cover - требует boto3 и MinIO
            import boto3
            from botocore.config import Config

            self._client = boto3.client(
                "s3",
                endpoint_url=self.s.s3_endpoint,
                aws_access_key_id=self.s.s3_access_key,
                aws_secret_access_key=self.s.s3_secret_key,
                region_name=self.s.s3_region,
                config=Config(
                    signature_version="s3v4",
                    retries={"max_attempts": self.s.http_retries, "mode": "standard"},
                    connect_timeout=int(self.s.http_timeout_seconds),
                    read_timeout=int(self.s.http_timeout_seconds),
                    # MinIO — внутренний адрес, прокси не используем (NO_PROXY)
                    proxies={},
                ),
            )
        return self._client

    def ensure_bucket(self) -> None:  # pragma: no cover - требует MinIO
        from botocore.exceptions import ClientError

        try:
            self._c().head_bucket(Bucket=self.bucket)
        except ClientError:
            try:
                self._c().create_bucket(Bucket=self.bucket)
                log.info("создан бакет MinIO", extra={"bucket": self.bucket})
            except ClientError as exc:
                raise UpstreamError(f"Не удалось создать бакет {self.bucket}: {exc}") from exc

    def put(
        self, key: str, data: bytes, *, content_type: str = "application/octet-stream"
    ) -> StoredObject:  # pragma: no cover - требует MinIO
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            self._c().put_object(Bucket=self.bucket, Key=key, Body=data, ContentType=content_type)
        except (ClientError, BotoCoreError) as exc:
            raise UpstreamError(f"Не удалось загрузить объект в MinIO: {exc}", key=key) from exc
        return StoredObject(bucket=self.bucket, key=key, size_bytes=len(data))

    def get(self, key: str) -> bytes:  # pragma: no cover - требует MinIO
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            return self._c().get_object(Bucket=self.bucket, Key=key)["Body"].read()
        except (ClientError, BotoCoreError) as exc:
            raise UpstreamError(f"Не удалось прочитать объект из MinIO: {exc}", key=key) from exc

    def delete(self, key: str) -> bool:  # pragma: no cover - требует MinIO
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            self._c().delete_object(Bucket=self.bucket, Key=key)
            return True
        except (ClientError, BotoCoreError) as exc:
            log.warning("не удалось удалить объект MinIO: %s", exc, extra={"key": key})
            return False

    def exists(self, key: str) -> bool:  # pragma: no cover - требует MinIO
        from botocore.exceptions import ClientError

        try:
            self._c().head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError:
            return False

    def list_objects(self, prefix: str = "") -> list[StoredObject]:  # pragma: no cover
        paginator = self._c().get_paginator("list_objects_v2")
        out: list[StoredObject] = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                out.append(
                    StoredObject(
                        bucket=self.bucket,
                        key=obj["Key"],
                        size_bytes=obj.get("Size", 0),
                        last_modified=obj.get("LastModified"),
                    )
                )
        return out


class InMemoryObjectStorage(ObjectStorage):
    """Реализация для тестов и локального прогона конвейера без MinIO."""

    def __init__(self, bucket: str = "packages") -> None:
        self._bucket = bucket
        self._objects: dict[str, tuple[bytes, datetime]] = {}

    @property
    def bucket(self) -> str:
        return self._bucket

    def ensure_bucket(self) -> None:
        return None

    def put(self, key: str, data: bytes, *, content_type: str = "application/octet-stream") -> StoredObject:
        from app.db.base import utcnow

        self._objects[key] = (data, utcnow())
        return StoredObject(bucket=self._bucket, key=key, size_bytes=len(data))

    def get(self, key: str) -> bytes:
        if key not in self._objects:
            raise UpstreamError(f"Объект {key} отсутствует во временном хранилище", key=key)
        return self._objects[key][0]

    def delete(self, key: str) -> bool:
        return self._objects.pop(key, None) is not None

    def exists(self, key: str) -> bool:
        return key in self._objects

    def list_objects(self, prefix: str = "") -> list[StoredObject]:
        return [
            StoredObject(bucket=self._bucket, key=k, size_bytes=len(v[0]), last_modified=v[1])
            for k, v in self._objects.items()
            if k.startswith(prefix)
        ]


_storage: ObjectStorage | None = None


def get_object_storage() -> ObjectStorage:
    global _storage
    if _storage is None:
        _storage = S3ObjectStorage()
    return _storage


def set_object_storage(storage: ObjectStorage | None) -> None:
    global _storage
    _storage = storage


def artifact_key(manager: str, name: str, version: str, filename: str) -> str:
    """Ключ объекта: `{manager}/{name}/{version}/{filename}`."""
    return f"{manager}/{name}/{version}/{filename}"
