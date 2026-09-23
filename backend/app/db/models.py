"""Схема данных сервиса модерации.

Типы намеренно переносимые (JSON вместо JSONB, строки вместо PG ENUM), чтобы
тот же код работал на PostgreSQL в бою и на SQLite в юнит-тестах. Ограничения
на допустимые значения — CheckConstraint по спискам из :mod:`app.db.enums`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.db.enums import (
    ARTIFACT_STATUSES,
    CLAIM_STATUSES,
    DEPENDENCY_KINDS,
    ITEM_STATUSES,
    MANAGER_CODES,
    REQUEST_SOURCES,
    REQUEST_STATUSES,
    ROLES,
    STEP_CODES,
    STEP_RESULTS,
    VERSION_STATUSES,
)


def _in(column: str, values: tuple[str, ...]) -> str:
    inner = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({inner})"


class User(Base, TimestampMixin):
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(primary_key=True)
    subject: Mapped[str | None] = mapped_column(String(255), unique=True)  # sub из OIDC
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(255))
    full_name: Mapped[str | None] = mapped_column(String(255))
    roles: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    is_service: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # GitLab (только чтение репозиториев); токены зашифрованы Fernet и не отдаются в API
    gitlab_username: Mapped[str | None] = mapped_column(String(255))
    gitlab_access_token_enc: Mapped[str | None] = mapped_column(Text)
    gitlab_refresh_token_enc: Mapped[str | None] = mapped_column(Text)
    gitlab_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def has_role(self, *roles: str) -> bool:
        return bool(set(self.roles or []) & set(roles))

    @property
    def display_name(self) -> str:
        return self.full_name or self.username


class PackageManager(Base):
    """Справочник поддерживаемых менеджеров (плагины: pypi, npm, go, nuget)."""

    __tablename__ = "package_manager"
    __table_args__ = (CheckConstraint(_in("code", MANAGER_CODES), name="manager_code"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_format: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Package(Base, TimestampMixin):
    __tablename__ = "package"
    __table_args__ = (
        UniqueConstraint("manager", "name", name="uq_package_manager_name"),
        Index("ix_package_name", "name"),
        CheckConstraint(_in("manager", MANAGER_CODES), name="manager_code"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    manager: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)  # нормализованное имя
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)  # как заявил разработчик
    confirmed_license_spdx: Mapped[str | None] = mapped_column(String(128))
    confirmed_license_version: Mapped[str | None] = mapped_column(String(128))

    versions: Mapped[list[PackageVersion]] = relationship(
        back_populates="package", cascade="all, delete-orphan"
    )


class PackageVersion(Base, TimestampMixin):
    __tablename__ = "package_version"
    __table_args__ = (
        UniqueConstraint("package_id", "version", name="uq_package_version_package_id"),
        Index("ix_package_version_status", "status"),
        Index("ix_package_version_quarantine_until", "quarantine_until"),
        CheckConstraint(_in("status", VERSION_STATUSES), name="version_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    package_id: Mapped[int] = mapped_column(ForeignKey("package.id", ondelete="CASCADE"), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)  # нормализованная
    raw_version: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="new", nullable=False)

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    quarantine_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    license_spdx: Mapped[str | None] = mapped_column(String(128))
    license_source: Mapped[str | None] = mapped_column(String(32))  # registry | claim | manual
    license_raw: Mapped[str | None] = mapped_column(Text)
    registry_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    vuln_index_version_id: Mapped[int | None] = mapped_column(ForeignKey("vuln_index_version.id"))
    max_vuln_score: Mapped[float | None] = mapped_column(Float)

    # Явное решение DevSecOps «публиковать несмотря на результат шага 5».
    # Без него возобновление конвейера снова упиралось бы в тот же вердикт, и
    # решение DevSecOps не имело бы эффекта.
    security_override_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    security_override_by_id: Mapped[int | None] = mapped_column(ForeignKey("user.id"))
    security_override_comment: Mapped[str | None] = mapped_column(Text)

    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status_reason: Mapped[str | None] = mapped_column(Text)

    package: Mapped[Package] = relationship(back_populates="versions")
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        back_populates="package_version", cascade="all, delete-orphan"
    )
    code_findings: Mapped[list[CodeFinding]] = relationship(
        back_populates="package_version", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="package_version", cascade="all, delete-orphan"
    )

    @property
    def manager(self) -> str:
        return self.package.manager

    @property
    def name(self) -> str:
        return self.package.name


class ModerationRequest(Base, TimestampMixin):
    __tablename__ = "moderation_request"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_moderation_request_idempotency_key"),
        Index("ix_moderation_request_status", "status"),
        CheckConstraint(_in("status", REQUEST_STATUSES), name="request_status"),
        CheckConstraint(_in("source", REQUEST_SOURCES), name="request_source"),
        CheckConstraint(_in("manager", MANAGER_CODES), name="manager_code"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    author_role: Mapped[str | None] = mapped_column(String(32))
    manager: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    source: Mapped[str] = mapped_column(String(16), default="api", nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(255))
    origin_file: Mapped[str | None] = mapped_column(String(512))
    include_transitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Итог раскрытия зависимостей: до какой глубины разошлись и что вышло.
    # Без этого нельзя показать «дерево обрезано по пределу» — а молчать об
    # этом нельзя: неполное дерево выглядит как полное.
    resolve_depth: Mapped[int | None] = mapped_column(SmallInteger)
    resolve_summary: Mapped[str | None] = mapped_column(Text)
    warnings: Mapped[list[str] | None] = mapped_column(JSON)

    author: Mapped[User] = relationship()
    items: Mapped[list[RequestItem]] = relationship(
        back_populates="request", cascade="all, delete-orphan", order_by="RequestItem.id"
    )


class RequestItem(Base, TimestampMixin):
    __tablename__ = "request_item"
    __table_args__ = (
        Index("ix_request_item_status", "status"),
        Index("ix_request_item_request_id", "request_id"),
        CheckConstraint(_in("status", ITEM_STATUSES), name="item_status"),
        CheckConstraint(_in("dependency_kind", DEPENDENCY_KINDS), name="dependency_kind"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[int] = mapped_column(
        ForeignKey("moderation_request.id", ondelete="CASCADE"), nullable=False
    )
    package_version_id: Mapped[int] = mapped_column(
        ForeignKey("package_version.id", ondelete="CASCADE"), nullable=False
    )
    requested_name: Mapped[str] = mapped_column(String(512), nullable=False)
    requested_version: Mapped[str] = mapped_column(String(128), nullable=False)
    dependency_kind: Mapped[str] = mapped_column(String(16), default="direct", nullable=False)
    # Дерево зависимостей внутри заявки: кто притащил этот пакет. Юристу и
    # DevSecOps это нужно постоянно — «эта GPL пришла через вот тот пакет»
    # другой разговор, чем «у нас в заявке GPL».
    parent_item_id: Mapped[int | None] = mapped_column(
        ForeignKey("request_item.id", ondelete="SET NULL"), nullable=True
    )
    depth: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    # required_range — требование родителя как есть («^4.17.21», «>=2,<4»):
    # по нему видно, почему выбрана именно эта версия.
    required_range: Mapped[str | None] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    current_step: Mapped[str | None] = mapped_column(String(32))
    next_action: Mapped[str | None] = mapped_column(Text)  # блок «Что делать» для разработчика
    blocked_reason: Mapped[str | None] = mapped_column(Text)
    waiting_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    request: Mapped[ModerationRequest] = relationship(back_populates="items")
    package_version: Mapped[PackageVersion] = relationship()
    steps: Mapped[list[PipelineStep]] = relationship(
        back_populates="item", cascade="all, delete-orphan", order_by="PipelineStep.step_order"
    )


class PipelineStep(Base):
    """Шаг конвейера с результатом, объяснением на русском и временем."""

    __tablename__ = "pipeline_step"
    __table_args__ = (
        UniqueConstraint("request_item_id", "step_code", name="uq_pipeline_step_request_item_id"),
        CheckConstraint(_in("step_code", STEP_CODES), name="step_code"),
        CheckConstraint(_in("result", STEP_RESULTS), name="step_result"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    request_item_id: Mapped[int] = mapped_column(
        ForeignKey("request_item.id", ondelete="CASCADE"), nullable=False
    )
    step_code: Mapped[str] = mapped_column(String(32), nullable=False)
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    result: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    message: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    item: Mapped[RequestItem] = relationship(back_populates="steps")


class VulnIndexVersion(Base):
    """Версия снапшота базы OSV, по которой вынесено решение."""

    __tablename__ = "vuln_index_version"

    id: Mapped[int] = mapped_column(primary_key=True)
    version: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    source: Mapped[str] = mapped_column(String(32), default="snapshot", nullable=False)
    checksum: Mapped[str | None] = mapped_column(String(128))
    remote_path: Mapped[str | None] = mapped_column(String(512))
    local_path: Mapped[str | None] = mapped_column(String(512))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    downloaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    record_count: Mapped[int | None] = mapped_column(Integer)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Vulnerability(Base):
    __tablename__ = "vulnerability"
    __table_args__ = (
        UniqueConstraint(
            "package_version_id", "external_id", name="uq_vulnerability_package_version_id"
        ),
        Index("ix_vulnerability_external_id", "external_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    package_version_id: Mapped[int] = mapped_column(
        ForeignKey("package_version.id", ondelete="CASCADE"), nullable=False
    )
    external_id: Mapped[str] = mapped_column(String(64), nullable=False)  # CVE / GHSA
    aliases: Mapped[list[str] | None] = mapped_column(JSON)
    summary: Mapped[str | None] = mapped_column(Text)
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # 0..100
    severity: Mapped[str | None] = mapped_column(String(16))
    url: Mapped[str | None] = mapped_column(String(1024))
    affected_ranges: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON)
    fixed_versions: Mapped[list[str] | None] = mapped_column(JSON)
    vuln_index_version_id: Mapped[int | None] = mapped_column(ForeignKey("vuln_index_version.id"))
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    package_version: Mapped[PackageVersion] = relationship(back_populates="vulnerabilities")


class CodeFinding(Base):
    """Находка сканера содержимого пакета: политический баннер или SAST.

    Отдельно от `vulnerability`: там уязвимости из базы OSV со своей
    нумерацией (CVE/GHSA) и баллом CVSS, здесь — срабатывание правила по
    исходникам с файлом и строкой. Сводить их в одну таблицу значило бы
    держать половину колонок пустыми у обоих.
    """

    __tablename__ = "code_finding"
    __table_args__ = (
        Index("ix_code_finding_package_version_id", "package_version_id"),
        Index("ix_code_finding_scanner", "scanner"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    package_version_id: Mapped[int] = mapped_column(
        ForeignKey("package_version.id", ondelete="CASCADE"), nullable=False
    )
    scanner: Mapped[str] = mapped_column(String(32), nullable=False)  # yara | semgrep
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="high", nullable=False)
    message: Mapped[str | None] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line: Mapped[int | None] = mapped_column(Integer)
    matched: Mapped[str | None] = mapped_column(Text)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    package_version: Mapped[PackageVersion] = relationship(back_populates="code_findings")


class License(Base):
    """Справочник SPDX: какие лицензии разрешены."""

    __tablename__ = "license"

    id: Mapped[int] = mapped_column(primary_key=True)
    spdx_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    name: Mapped[str | None] = mapped_column(String(255))
    allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    url: Mapped[str | None] = mapped_column(String(1024))
    notes: Mapped[str | None] = mapped_column(Text)


class LicenseClaim(Base, TimestampMixin):
    """Заявление лицензии разработчиком для пакета, остановленного на шаге 3."""

    __tablename__ = "license_claim"
    __table_args__ = (CheckConstraint(_in("status", CLAIM_STATUSES), name="claim_status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    package_version_id: Mapped[int] = mapped_column(
        ForeignKey("package_version.id", ondelete="CASCADE"), nullable=False
    )
    request_item_id: Mapped[int | None] = mapped_column(ForeignKey("request_item.id", ondelete="SET NULL"))
    claimed_by_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    snapshot_text: Mapped[str | None] = mapped_column(Text)
    snapshot_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    spdx_id: Mapped[str | None] = mapped_column(String(128))
    comment: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("user.id"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_comment: Mapped[str | None] = mapped_column(Text)

    package_version: Mapped[PackageVersion] = relationship()
    claimed_by: Mapped[User] = relationship(foreign_keys=[claimed_by_id])
    decided_by: Mapped[User | None] = relationship(foreign_keys=[decided_by_id])


class Comment(Base, TimestampMixin):
    """Обсуждение: ветка на заявку целиком и на каждый её пакет."""

    __tablename__ = "comment"
    __table_args__ = (Index("ix_comment_request_id", "request_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[int] = mapped_column(
        ForeignKey("moderation_request.id", ondelete="CASCADE"), nullable=False
    )
    request_item_id: Mapped[int | None] = mapped_column(ForeignKey("request_item.id", ondelete="CASCADE"))
    author_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    author_role: Mapped[str | None] = mapped_column(String(32))
    body: Mapped[str] = mapped_column(Text, nullable=False)  # markdown
    mentions: Mapped[list[str] | None] = mapped_column(JSON)
    is_edited: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    edited_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    author: Mapped[User] = relationship()


class Artifact(Base):
    """Артефакт: ключ в MinIO (временно) и URL в Nexus (постоянно)."""

    __tablename__ = "artifact"
    __table_args__ = (
        Index("ix_artifact_package_version_id", "package_version_id"),
        CheckConstraint(_in("status", ARTIFACT_STATUSES), name="artifact_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    package_version_id: Mapped[int] = mapped_column(
        ForeignKey("package_version.id", ondelete="CASCADE"), nullable=False
    )
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(2048))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(128))
    declared_checksum: Mapped[str | None] = mapped_column(String(160))
    checksum_algo: Mapped[str | None] = mapped_column(String(16))
    # Столбцы переименованы миграцией 0015 (S3 выведен из эксплуатации:
    # промежуточная зона теперь в артефактори). Имена атрибутов оставлены
    # прежними намеренно — их читает весь остальной код python-версии, и
    # переименовывать его ради снятой системы незачем: python-версия
    # доживает до конца переноса на Go.
    s3_bucket: Mapped[str | None] = mapped_column("staging_repo", String(128))
    s3_key: Mapped[str | None] = mapped_column("staging_path", String(1024))
    s3_uploaded_at: Mapped[datetime | None] = mapped_column(
        "staged_at", DateTime(timezone=True)
    )
    s3_deleted_at: Mapped[datetime | None] = mapped_column(
        "staging_cleared_at", DateTime(timezone=True)
    )
    nexus_url: Mapped[str | None] = mapped_column(String(2048))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default="downloaded", nullable=False)

    package_version: Mapped[PackageVersion] = relationship(back_populates="artifacts")


class Notification(Base):
    __tablename__ = "notification"
    __table_args__ = (Index("ix_notification_user_id_read_at", "user_id", "read_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[int | None] = mapped_column(ForeignKey("moderation_request.id", ondelete="CASCADE"))
    request_item_id: Mapped[int | None] = mapped_column(ForeignKey("request_item.id", ondelete="CASCADE"))
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    """Кто, что, когда, старое/новое значение, источник (UI / REST API / фоновая задача)."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_entity", "entity_type", "entity_id"),
        Index("ix_audit_log_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("user.id", ondelete="SET NULL"))
    actor_name: Mapped[str] = mapped_column(String(255), default="system", nullable=False)
    actor_role: Mapped[str | None] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(64))
    old_value: Mapped[Any | None] = mapped_column(JSON)
    new_value: Mapped[Any | None] = mapped_column(JSON)
    source: Mapped[str] = mapped_column(String(16), default="api", nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))  # correlation id
    ip: Mapped[str | None] = mapped_column(String(64))
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


__all__ = [
    "ROLES",
    "Artifact",
    "AuditLog",
    "Comment",
    "License",
    "LicenseClaim",
    "ModerationRequest",
    "Notification",
    "Package",
    "PackageManager",
    "PackageVersion",
    "PipelineStep",
    "RequestItem",
    "User",
    "VulnIndexVersion",
    "Vulnerability",
]
