from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# --------------------------------------------------------------------------- заявки
class PackageItemIn(ApiModel):
    name: str = Field(min_length=1, max_length=512)
    version: str = Field(min_length=1, max_length=128)


class CreateRequestIn(ApiModel):
    manager: str = Field(description="pypi | npm | go | nuget")
    packages: list[PackageItemIn | str] = Field(
        default_factory=list,
        description="Список пакетов: объекты {name, version} или строки формата менеджера",
    )
    reason: str | None = Field(default=None, max_length=2000)

    @field_validator("manager")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class ParsedPackageOut(ApiModel):
    raw: str
    state: str = Field(description="new | already_in_base | invalid_format")
    name: str | None = None
    version: str | None = None
    dependency_kind: str = "direct"
    message: str | None = None
    expected_format: str | None = None
    package_version_id: int | None = None
    status: str | None = None
    link: str | None = None
    install_command: str | None = None


class CreateRequestOut(ApiModel):
    request_id: int
    manager: str
    status: str
    accepted: int
    skipped_already_in_base: int
    invalid: int
    warnings: list[str] = Field(default_factory=list)
    packages: list[ParsedPackageOut]
    status_url: str


class StepOut(ApiModel):
    code: str
    order: int
    title: str
    result: str
    message: str | None = None
    details: dict[str, Any] | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class VulnOut(ApiModel):
    id: str
    score: float
    cvss_vector: str | None = None
    severity: str | None = None
    url: str | None = None
    summary: str | None = None
    fixed_versions: list[str] | None = None


class CodeFindingOut(ApiModel):
    """Находка сканера содержимого: политический баннер или срабатывание SAST."""

    scanner: str  # yara | semgrep
    rule_id: str
    severity: str
    message: str | None = None
    file: str | None = None
    line: int | None = None
    matched: str | None = None


class RequestItemOut(ApiModel):
    id: int
    package_version_id: int
    name: str
    version: str
    dependency_kind: str
    status: str
    status_title: str
    # Коды шагов, по которым решение роли ещё не получено: `license` — юристы,
    # `vuln_scan` — DevSecOps, `quarantine` — срок карантина. Их может быть
    # несколько сразу, поэтому статуса (он один) для интерфейса недостаточно.
    pending: list[str] = Field(default_factory=list)
    current_step: str | None = None
    current_step_title: str | None = None
    blocked_reason: str | None = None
    next_action: str | None = None
    waiting_since: datetime | None = None
    finished_at: datetime | None = None
    license_spdx: str | None = None
    quarantine_until: datetime | None = None
    max_vuln_score: float | None = None
    install_command: str | None = None
    vulnerabilities: list[VulnOut] = Field(default_factory=list)
    code_findings: list[CodeFindingOut] = Field(default_factory=list)
    steps: list[StepOut] = Field(default_factory=list)


class RequestOut(ApiModel):
    request_id: int
    manager: str
    status: str
    status_title: str
    approved: bool
    author: str | None = None
    author_role: str | None = None
    reason: str | None = None
    source: str
    origin_file: str | None = None
    include_transitive: bool = False
    warnings: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    summary: dict[str, Any]
    packages: list[RequestItemOut]


class RequestListItem(ApiModel):
    request_id: int
    manager: str
    status: str
    status_title: str
    author: str | None
    reason: str | None
    created_at: datetime
    total: int
    approved: int


# --------------------------------------------------------------------------- пакеты
class CheckPackagesIn(ApiModel):
    manager: str
    packages: list[PackageItemIn | str] = Field(default_factory=list)


class PackageVersionOut(ApiModel):
    id: int
    manager: str
    name: str
    normalized_name: str
    version: str
    status: str
    license_spdx: str | None = None
    license_source: str | None = None
    published_at: datetime | None = None
    quarantine_until: datetime | None = None
    approved_at: datetime | None = None
    max_vuln_score: float | None = None
    status_reason: str | None = None
    install_command: str | None = None
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)


class PackageSearchOut(ApiModel):
    total: int
    limit: int
    offset: int
    items: list[PackageVersionOut]


# --------------------------------------------------------------------------- решения
class SecurityDecisionIn(ApiModel):
    approve: bool
    comment: str | None = Field(default=None, max_length=4000)


class QuarantineReleaseIn(ApiModel):
    comment: str | None = Field(default=None, max_length=4000)


class LicenseClaimIn(ApiModel):
    url: str = Field(min_length=8, max_length=1024)
    spdx_id: str | None = Field(default=None, max_length=128)
    comment: str | None = Field(default=None, max_length=4000)


class LicenseDecisionIn(ApiModel):
    approve: bool
    comment: str | None = Field(default=None, max_length=4000)


class LicenseClaimOut(ApiModel):
    id: int
    package_version_id: int
    request_item_id: int | None
    package: str | None = None
    version: str | None = None
    manager: str | None = None
    url: str
    spdx_id: str | None
    comment: str | None
    status: str
    snapshot_text: str | None = None
    snapshot_fetched_at: datetime | None = None
    claimed_by: str | None = None
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_comment: str | None = None
    created_at: datetime
    suggested_license: dict[str, Any] | None = None


# --------------------------------------------------------------------------- обсуждения
class CommentIn(ApiModel):
    body: str = Field(min_length=1, max_length=10000)
    request_item_id: int | None = None


class CommentUpdateIn(ApiModel):
    body: str = Field(min_length=1, max_length=10000)


class CommentOut(ApiModel):
    id: int
    request_id: int
    request_item_id: int | None
    author: str
    author_role: str | None
    body: str
    mentions: list[str] = Field(default_factory=list)
    is_edited: bool
    edited_at: datetime | None
    deleted: bool
    created_at: datetime
    can_edit: bool = False


# --------------------------------------------------------------------------- очереди
class QueueItemOut(ApiModel):
    item_id: int
    request_id: int
    manager: str
    name: str
    version: str
    status: str
    status_title: str
    current_step: str | None
    blocked_reason: str | None
    waiting_since: datetime | None
    waiting_hours: float | None
    author: str | None
    license_spdx: str | None = None
    max_vuln_score: float | None = None
    license_claim_id: int | None = None


# --------------------------------------------------------------------------- уведомления
class NotificationOut(ApiModel):
    id: int
    event: str
    title: str
    body: str | None
    request_id: int | None
    request_item_id: int | None
    created_at: datetime
    read_at: datetime | None


class NotificationsOut(ApiModel):
    unread: int
    items: list[NotificationOut]


class MarkReadIn(ApiModel):
    ids: list[int] | None = None
    all: bool = False


# --------------------------------------------------------------------------- прочее
class MeOut(ApiModel):
    id: int
    username: str
    display_name: str
    email: str | None
    roles: list[str]
    is_service: bool
    gitlab_connected: bool = False


class LocalLoginIn(ApiModel):
    username: str
    password: str


class TokenOut(ApiModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    roles: list[str]


class SettingOut(ApiModel):
    env: str
    section: str
    description: str
    value: Any
    secret: bool


class AuditOut(ApiModel):
    id: int
    actor_name: str
    actor_role: str | None
    action: str
    entity_type: str
    entity_id: str | None
    old_value: Any = None
    new_value: Any = None
    source: str
    source_title: str | None = None
    comment: str | None
    ip: str | None
    created_at: datetime


class ManagerOut(ApiModel):
    code: str
    title: str
    entry_format: str
    dependency_files: list[str]
    osv_ecosystem: str


class GitlabFileIn(ApiModel):
    project: str = Field(description="ID или path_with_namespace проекта GitLab")
    path: str = Field(description="Путь к файлу зависимостей в репозитории")
    ref: str = Field(default="HEAD", description="Ветка, тег или commit sha")
    manager: str | None = None
    reason: str | None = None
    include_transitive: bool = False
