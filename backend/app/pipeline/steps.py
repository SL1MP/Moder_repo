"""Шаги конвейера проверок. Порядок строгий, первый `fail` останавливает конвейер.

0. Проверка наличия в базе
1. Blacklist        — пакет не скачивается, наружу сервис не ходит
2. Карантин         — метаданные из реестра
3. Лицензия         — SPDX из метаданных против справочника
4. Скачивание       — напрямую из реестра через HTTP_PROXY, в MinIO
5. Уязвимости       — osv-scanner по снапшоту OSV
6. Баннеры          — политический протестварь по правилам YARA
7. SAST             — статический анализ исходников пакета
8. Выгрузка         — публикация в артефактори, удаление объекта из MinIO
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import timedelta

from app.adapters.artifact_store import get_artifact_store
from app.adapters.content_scan import (
    SEVERITY_ORDER,
    ScanOutcome,
    get_banner_scanner,
    get_sast_scanner,
)
from app.adapters.notifier import Event
from app.adapters.object_storage import artifact_key, get_object_storage
from app.adapters.osv_scanner import scan_artifact
from app.core.errors import AppError, UpstreamError
from app.core.http import client, request_with_retries
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.enums import STEP_TITLES
from app.db.models import (
    Artifact,
    CodeFinding,
    LicenseClaim,
    User,
    Vulnerability,
    VulnIndexVersion,
)
from app.pipeline.blockers import (
    BLOCKER_ROLE,
    BLOCKER_STATUS,
    BLOCKER_WAITING_FOR,
    pending_blockers,
)
from app.pipeline.context import PipelineContext, StepOutcome
from app.services.artifact_unpack import UnpackLimits, cleanup, unpack_artifact
from app.services.policies import get_blacklist, get_license_policy

log = get_logger(__name__)


class PipelineStepHandler(ABC):
    code: str
    title: str

    @abstractmethod
    def run(self, ctx: PipelineContext) -> StepOutcome: ...


# --------------------------------------------------------------------------- шаг 0
class DbCheckStep(PipelineStepHandler):
    code = "db_check"
    title = "Проверка наличия в базе"

    def run(self, ctx: PipelineContext) -> StepOutcome:
        if ctx.version.status == "approved":
            plugin = ctx.plugin
            repo = ctx.settings.artifact_repo(ctx.package.manager)
            command = plugin.install_command(ctx.ref, ctx.settings.artifact_base_url, repo)
            return StepOutcome(
                result="pass",
                message=f"{ctx.label} уже одобрен и опубликован во внутреннем репозитории.",
                details={"install_command": command, "already_in_base": True},
                stop=True,
                terminal=True,
                item_status="approved",
                version_status="approved",
                next_action=f"Устанавливайте из внутреннего репозитория: {command}",
            )
        if ctx.version.status == "blacklisted":
            return StepOutcome.fail(
                f"{ctx.label} ранее запрещён правилами blacklist.",
                item_status="blacklisted",
                version_status="blacklisted",
                next_action="Согласуйте замену пакета с DevSecOps — решение окончательное.",
            )
        if ctx.version.status == "revoked":
            return StepOutcome.fail(
                f"{ctx.label} был отозван: {ctx.version.status_reason or 'причина не указана'}.",
                item_status="revoked",
                version_status="revoked",
                next_action="Возьмите более новую версию либо согласуйте исключение с DevSecOps.",
            )
        return StepOutcome.ok(f"{ctx.label} в базе не найден, заявка принята к проверке.")


# --------------------------------------------------------------------------- шаг 1
class BlacklistStep(PipelineStepHandler):
    code = "blacklist"
    title = "Blacklist"

    def run(self, ctx: PipelineContext) -> StepOutcome:
        blacklist = get_blacklist()
        rule = blacklist.find(ctx.package.manager, ctx.package.name, ctx.version.version)
        if rule is None:
            return StepOutcome.ok(
                f"Совпадений с правилами blacklist нет (правил загружено: {len(blacklist.rules)})."
            )
        return StepOutcome.fail(
            f"Пакет запрещён правилом blacklist «{rule.name}» ({rule.versions}): {rule.reason}",
            details={"rule": rule.as_dict()},
            item_status="blacklisted",
            version_status="blacklisted",
            next_action=(
                "Решение окончательное: пакет не скачивается. Подберите разрешённую замену. "
                "Снять запрет можно только правкой blacklist (admin/devsecops)."
            ),
            notify_event=Event.DECISION_MADE,
        )


# --------------------------------------------------------------------------- шаг 2
class QuarantineStep(PipelineStepHandler):
    code = "quarantine"
    title = "Карантин"

    def run(self, ctx: PipelineContext) -> StepOutcome:
        meta = fetch_metadata_cached(ctx)
        version = ctx.version
        version.published_at = meta.published_at
        version.registry_metadata = {
            "artifact_url": meta.artifact_url,
            "artifact_filename": meta.artifact_filename,
            "checksum": meta.checksum,
            "checksum_algo": meta.checksum_algo,
            "size_bytes": meta.size_bytes,
            "license_raw": meta.license_raw,
            "license_spdx": meta.license_spdx,
            "yanked": meta.yanked,
            **(meta.raw or {}),
        }
        days = ctx.settings.quarantine_days

        if meta.published_at is None:
            return StepOutcome.warn(
                "Реестр не сообщил дату публикации версии — автоматически проверить карантин "
                f"({days} дн.) невозможно.",
                item_status="awaiting_security",
                version_status="awaiting_security",
                next_action="Дождитесь решения DevSecOps: срок карантина подтверждается вручную.",
                notify_roles=["devsecops"],
                notify_event=Event.REQUEST_AWAITS_SECURITY,
                details={"reason": "unknown_publish_date"},
            )

        age = utcnow() - meta.published_at
        if age >= timedelta(days=days):
            version.quarantine_until = None
            return StepOutcome.ok(
                f"Версия опубликована {meta.published_at.date().isoformat()} "
                f"({age.days} дн. назад) — карантин {days} дн. пройден."
            )

        until = meta.published_at + timedelta(days=days)
        version.quarantine_until = until
        left = max((until - utcnow()).days, 0)
        return StepOutcome.warn(
            f"Версия опубликована {meta.published_at.date().isoformat()} "
            f"({age.days} дн. назад), карантин {days} дн. не истёк.",
            details={
                "published_at": meta.published_at.isoformat(),
                "quarantine_until": until.isoformat(),
                "days_left": left,
            },
            item_status="quarantined",
            version_status="quarantined",
            next_action=(
                f"Карантин закончится {until.date().isoformat()} (осталось {left} дн.) — проверка "
                "продолжится автоматически. Досрочно карантин может снять DevSecOps."
            ),
            notify_event=Event.DECISION_MADE,
        )


# --------------------------------------------------------------------------- шаг 3
class LicenseStep(PipelineStepHandler):
    code = "license"
    title = "Лицензия"

    def run(self, ctx: PipelineContext) -> StepOutcome:
        policy = get_license_policy()
        version = ctx.version

        claim = (
            ctx.session.query(LicenseClaim)
            .filter(
                LicenseClaim.package_version_id == version.id,
                LicenseClaim.status == "approved",
            )
            .order_by(LicenseClaim.decided_at.desc())
            .first()
        )
        if claim is not None:
            version.license_spdx = claim.spdx_id or version.license_spdx
            version.license_source = "claim"
            return StepOutcome.ok(
                f"Лицензия подтверждена юристами: {version.license_spdx or 'по ссылке'} "
                f"(заявление #{claim.id})."
            )

        meta = fetch_metadata_cached(ctx)
        spdx = meta.license_spdx
        version.license_raw = meta.license_raw
        if spdx:
            version.license_spdx = spdx
            version.license_source = "registry"

        if spdx and policy.is_allowed(spdx):
            return StepOutcome.ok(f"Лицензия {spdx} есть в справочнике разрешённых.")

        confirmed = ctx.package.confirmed_license_spdx
        hint = ""
        if confirmed:
            hint = (
                f" Для этого пакета ранее подтверждена лицензия {confirmed} "
                f"(версия {ctx.package.confirmed_license_version}) — подтверждение было для "
                "другой версии."
            )
        if not spdx:
            message = "Лицензия не определилась по метаданным реестра." + hint
            reason = "license_unknown"
        else:
            message = f"Лицензия {spdx} отсутствует в справочнике разрешённых." + hint
            reason = "license_not_allowed"

        # Конвейер не останавливается: пакет уходит на скачивание и проверку
        # уязвимостей, чтобы DevSecOps увидел его в своей очереди сразу, а не
        # после решения юриста. Опубликован он не будет, пока лицензия не
        # согласована — это проверяет шаг публикации.
        return StepOutcome.pending(
            message,
            details={
                "spdx": spdx,
                "license_raw": meta.license_raw,
                "reason": reason,
                "confirmed_for_other_version": confirmed,
            },
            item_status="awaiting_legal",
            version_status="awaiting_legal",
            next_action=(
                "Приложите ссылку на файл лицензии или страницу проекта в карточке пакета — "
                "заявка уйдёт юристам. Проверка на уязвимости идёт параллельно."
            ),
            notify_roles=["legal"],
            notify_event=Event.REQUEST_AWAITS_LEGAL,
        )


# --------------------------------------------------------------------------- шаг 4
class DownloadStep(PipelineStepHandler):
    code = "download"
    title = "Скачивание артефакта"

    def run(self, ctx: PipelineContext) -> StepOutcome:
        meta = fetch_metadata_cached(ctx)
        if not meta.artifact_url:
            return StepOutcome.fail(
                "Реестр не сообщил URL артефакта — скачать пакет невозможно.",
                item_status="failed",
                version_status="failed",
                next_action="Проверьте, что версия опубликована в реестре, и повторите заявку.",
            )
        filename = meta.artifact_filename or f"{ctx.package.name}-{ctx.version.raw_version}"
        limit = ctx.settings.max_artifact_size_bytes

        # Качаем напрямую из реестра пакетного менеджера (не через proxy-репозиторий
        # артефактори), через корпоративный HTTP_PROXY.
        payload = _download(meta.artifact_url, limit, ctx.package.manager)
        digest = hashlib.sha256(payload).hexdigest()

        checksum_ok: bool | None = None
        if meta.checksum and meta.checksum_algo:
            expected = meta.checksum.lower().strip()
            actual = hashlib.new(_hash_algo(meta.checksum_algo), payload).hexdigest()
            checksum_ok = actual == expected
            if not checksum_ok:
                return StepOutcome.fail(
                    f"Контрольная сумма артефакта не совпала с заявленной в реестре "
                    f"({meta.checksum_algo}): ожидалось {expected[:16]}…, получено {actual[:16]}….",
                    details={"expected": expected, "actual": actual, "algo": meta.checksum_algo},
                    item_status="failed",
                    version_status="failed",
                    next_action="Повторите заявку позже: артефакт в реестре мог быть перезалит.",
                )

        key = artifact_key(ctx.package.manager, ctx.package.name, ctx.version.raw_version, filename)
        storage = get_object_storage()
        storage.put(key, payload)

        artifact = _get_or_create_artifact(ctx, filename)
        artifact.source_url = meta.artifact_url
        artifact.size_bytes = len(payload)
        artifact.sha256 = digest
        artifact.declared_checksum = meta.checksum
        artifact.checksum_algo = meta.checksum_algo
        artifact.s3_bucket = storage.bucket
        artifact.s3_key = key
        artifact.s3_uploaded_at = utcnow()
        artifact.s3_deleted_at = None
        artifact.status = "downloaded"
        ctx.session.flush()
        ctx.cache["artifact_payload"] = payload

        checksum_note = {
            True: f"контрольная сумма {meta.checksum_algo} совпала",
            False: "контрольная сумма не проверялась",
            None: "реестр не сообщил контрольную сумму",
        }[checksum_ok]
        return StepOutcome.ok(
            f"Артефакт {filename} ({len(payload) // 1024} КБ) скачан из реестра, {checksum_note}; "
            f"помещён во временное хранилище: {key}",
            details={"s3_key": key, "sha256": digest, "size_bytes": len(payload)},
        )


def _hash_algo(algo: str) -> str:
    return {"sha1": "sha1", "sha256": "sha256", "sha512": "sha512", "md5": "md5"}.get(
        algo.lower(), "sha256"
    )


def _download(url: str, limit: int, manager: str) -> bytes:
    with client() as http:
        resp = request_with_retries(f"registry-{manager}", lambda: http.get(url))
        if resp.status_code >= 400:
            raise UpstreamError(
                f"Реестр ответил {resp.status_code} при скачивании артефакта", status=resp.status_code
            )
        declared = resp.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise UpstreamError(
                f"Размер артефакта {int(declared)} байт превышает лимит {limit} байт",
                size=int(declared),
                limit=limit,
            )
        payload = resp.content
    if len(payload) > limit:
        raise UpstreamError(
            f"Размер артефакта {len(payload)} байт превышает лимит {limit} байт",
            size=len(payload),
            limit=limit,
        )
    return payload


def _get_or_create_artifact(ctx: PipelineContext, filename: str) -> Artifact:
    artifact = next(
        (a for a in ctx.version.artifacts if a.filename == filename),
        None,
    )
    if artifact is None:
        artifact = Artifact(package_version_id=ctx.version.id, filename=filename)
        ctx.session.add(artifact)
        ctx.version.artifacts.append(artifact)
        ctx.session.flush()
    return artifact


# --------------------------------------------------------------------------- шаг 5
class VulnScanStep(PipelineStepHandler):
    code = "vuln_scan"
    title = "Проверка на уязвимости"

    def run(self, ctx: PipelineContext) -> StepOutcome:
        index = ctx.vuln_index
        artifact = _current_artifact(ctx)
        if artifact is None:
            return StepOutcome.fail(
                "Артефакт для проверки не найден — шаг скачивания не выполнен.",
                item_status="failed",
                version_status="failed",
                next_action="Перезапустите проверку заявки.",
            )

        info = index.current_version()
        index_row = _upsert_index_version(ctx, info)
        max_days = ctx.settings.osv_max_staleness_days
        stale = index.is_stale(max_days)

        payload = ctx.cache.get("artifact_payload")
        if payload is None:
            payload = get_object_storage().get(artifact.s3_key or "")
            ctx.cache["artifact_payload"] = payload

        # Сканировать есть смысл только если данные вообще загружены: при отсутствующем
        # снапшоте запрос к индексу выбросит ошибку, а по заданию недоступная база — не
        # техническая авария, а повод отдать решение DevSecOps (warn ниже).
        result = None
        scan_error: str | None = None
        if info is not None:
            try:
                result = scan_artifact(
                    manager=ctx.package.manager,
                    name=ctx.package.name,
                    version=ctx.version.version,
                    filename=artifact.filename,
                    payload=payload,
                    index=index,
                )
            except AppError as exc:
                if not stale:
                    raise  # база свежая, а скан не удался — это уже настоящая ошибка
                scan_error = exc.message
        else:
            scan_error = "снапшот базы OSV ни разу не загружался"

        findings = result.findings if result else []
        _store_findings(ctx, findings, index_row)
        artifact.status = "scanned"
        threshold = ctx.settings.vuln_max_score
        worst = max((f.score for f in findings), default=0.0)
        ctx.version.max_vuln_score = worst
        ctx.version.vuln_index_version_id = index_row.id if index_row else None
        summary = _findings_summary(findings)

        # Явное решение DevSecOps важнее вердикта шага: иначе возобновление конвейера
        # снова остановилось бы здесь по той же причине, и решение не сработало бы.
        if ctx.version.security_override_at is not None:
            decided_by = (
                ctx.version.security_override_by_id
                and ctx.session.get(User, ctx.version.security_override_by_id)
            )
            who = decided_by.display_name if decided_by else "DevSecOps"
            return StepOutcome.ok(
                f"Публикация разрешена вручную ({who}): "
                f"{ctx.version.security_override_comment or 'без комментария'}."
                + (f" Известные уязвимости: {summary}." if summary else ""),
                details={
                    "reason": "security_override",
                    "decided_by": who,
                    "decided_at": ctx.version.security_override_at.isoformat(),
                    "comment": ctx.version.security_override_comment,
                    "max_score": worst,
                    "threshold": threshold,
                    "findings": summary,
                    "index_version": info.version if info else None,
                },
            )

        if stale:
            # Молча одобрять на устаревших данных нельзя.
            age = info.age_days() if info else None
            age_text = f"{age:.1f} дн." if age is not None else "снапшот не загружен"
            return StepOutcome.warn(
                f"База уязвимостей устарела ({age_text}, допустимо {max_days} дн.) — "
                "автоматическое одобрение отключено."
                + (f" Найдено: {summary}" if summary else "")
                + (f" Проверка не выполнена: {scan_error}" if scan_error else ""),
                details={
                    "reason": "stale_index",
                    "index_version": info.version if info else None,
                    "age_days": age,
                    "findings": summary,
                    "scanner": result.scanner if result else None,
                    "scan_error": scan_error,
                },
                item_status="awaiting_security",
                version_status="awaiting_security",
                next_action="Дождитесь решения DevSecOps: решение по устаревшей базе принимается вручную.",
                notify_roles=["devsecops"],
                notify_event=Event.REQUEST_AWAITS_SECURITY,
            )

        if worst > threshold:
            # Отклонение на шаге 5: объект из MinIO удаляется сразу.
            purge_artifact(ctx, artifact, reason="Отклонён на шаге проверки уязвимостей")
            return StepOutcome.fail(
                f"Найдены уязвимости с баллом выше порога {threshold:g}: {summary}. "
                f"Решение вынесено по снапшоту OSV {info.version if info else 'н/д'}.",
                details={
                    "max_score": worst,
                    "threshold": threshold,
                    "index_version": info.version if info else None,
                    "scanner": result.scanner if result else None,
                    "findings": [
                        {
                            "id": f.external_id,
                            "score": f.score,
                            "cvss": f.cvss_vector,
                            "fixed": f.fixed_versions,
                            "url": f.url,
                        }
                        for f in findings
                    ],
                },
                item_status="awaiting_security",
                version_status="awaiting_security",
                next_action=(
                    "Возьмите версию с исправлением "
                    + (
                        ", ".join(sorted({v for f in findings for v in f.fixed_versions}))
                        or "(исправленных версий нет)"
                    )
                    + " либо дождитесь решения DevSecOps."
                ),
                notify_roles=["devsecops"],
                notify_event=Event.REQUEST_AWAITS_SECURITY,
            )

        message = (
            f"Уязвимостей выше порога {threshold:g} не найдено"
            + (f" (учтено: {summary})" if summary else "")
            + f". Снапшот OSV: {info.version if info else 'н/д'}, "
            + f"сканер: {result.scanner if result else 'н/д'}."
        )
        return StepOutcome.ok(
            message,
            details={
                "max_score": worst,
                "threshold": threshold,
                "index_version": info.version if info else None,
                "scanner": result.scanner if result else None,
                "findings_count": len(findings),
            },
        )


def _findings_summary(findings: list) -> str:
    return ", ".join(f"{f.external_id} ({f.score:g})" for f in findings) if findings else ""


def _current_artifact(ctx: PipelineContext) -> Artifact | None:
    artifacts = [a for a in ctx.version.artifacts if a.s3_key or a.nexus_url]
    if not artifacts:
        return None
    return sorted(artifacts, key=lambda a: (a.s3_deleted_at is not None, a.id))[0]


def _upsert_index_version(ctx: PipelineContext, info) -> VulnIndexVersion | None:
    if info is None:
        return None
    row = (
        ctx.session.query(VulnIndexVersion).filter(VulnIndexVersion.version == info.version).first()
    )
    if row is None:
        row = VulnIndexVersion(
            version=info.version,
            source=info.source,
            checksum=info.checksum,
            remote_path=info.remote_path,
            local_path=info.local_path,
            published_at=info.published_at,
            downloaded_at=utcnow(),
            record_count=info.record_count,
            is_active=True,
        )
        ctx.session.add(row)
        ctx.session.flush()
    return row


def _store_findings(ctx: PipelineContext, findings: list, index_row: VulnIndexVersion | None) -> None:
    existing = {v.external_id: v for v in ctx.version.vulnerabilities}
    for finding in findings:
        row = existing.get(finding.external_id)
        if row is None:
            row = Vulnerability(
                package_version_id=ctx.version.id, external_id=finding.external_id
            )
            ctx.session.add(row)
            ctx.version.vulnerabilities.append(row)
        row.summary = finding.summary
        row.aliases = finding.aliases or None
        row.cvss_vector = finding.cvss_vector
        row.cvss_score = finding.cvss_score
        row.score = finding.score
        row.severity = finding.severity
        row.url = finding.url
        row.affected_ranges = finding.affected_ranges or None
        row.fixed_versions = finding.fixed_versions or None
        row.vuln_index_version_id = index_row.id if index_row else None
        row.detected_at = utcnow()
    ctx.session.flush()


# --------------------------------------------------------------------------- шаг 6
# --------------------------------------------------------------------------- шаги 6-7
class _ContentScanStep(PipelineStepHandler):
    """Общая часть сканеров содержимого: распаковка, прогон, разбор находок.

    Блокирующий сканер отдаёт решение DevSecOps, а не отклоняет пакет сам:
    политический баннер — повод посмотреть глазами, а не безусловный запрет.
    Конвейер при этом не останавливается (`pending`), чтобы DevSecOps увидел
    все находки разом, а не по одной за прогон.

    Информационный сканер (``advisory``) публикацию не блокирует вообще —
    см. одноимённое поле и SastScanStep.
    """

    scanner_name: str
    enabled_setting: str
    # advisory — шаг информационный: находки сохраняются, но публикацию не
    # задерживают и решения роли не требуют. Так устроен SAST, см. SastScanStep.
    advisory: bool = False

    def _scanner(self):  # pragma: no cover - переопределяется наследником
        raise NotImplementedError

    def _advise(self, ctx: PipelineContext, outcome: ScanOutcome) -> StepOutcome:
        """Исход информационного шага: публикацию не задерживает никогда."""
        threshold = self._min_severity(ctx)
        total = len(outcome.findings)
        if not outcome.available:
            # `pass` здесь означал бы «проверено, находок нет», а проверки не
            # было; позвать DevSecOps нельзя — шаг не блокирующий. Значит,
            # единственная защита от незаметной потери проверки — сказать это
            # в карточке.
            return StepOutcome.info(
                f"{self.title}: проверка НЕ выполнена ({outcome.detail}), поэтому "
                "отсутствие находок ничего не значит. Публикацию шаг не блокирует — "
                "он информационный.",
                details={"reason": "scanner_unavailable", "advisory": True,
                         "detail": outcome.detail},
            )
        if total:
            blocking = [
                f
                for f in outcome.findings
                if SEVERITY_ORDER.index(f.severity) >= SEVERITY_ORDER.index(threshold)
            ]
            rules = sorted({f.rule_id for f in outcome.findings[:20]})
            return StepOutcome.info(
                f"{self.title}: найдено срабатываний — {total} "
                f"(выше порога «{threshold}»: {len(blocking)}; правила: {', '.join(rules)}). "
                "Публикацию не блокирует — шаг информационный, находки смотрите в отчёте.",
                details={
                    "reason": "findings",
                    "advisory": True,
                    "findings_total": total,
                    "findings_blocking": len(blocking),
                    "threshold": threshold,
                    "rules": rules,
                },
            )
        return StepOutcome.ok(
            f"{self.title}: срабатываний нет. {outcome.detail}.",
            details={"advisory": True, "threshold": threshold, "detail": outcome.detail},
        )

    def _min_severity(self, ctx: PipelineContext) -> str:
        return "info"

    def run(self, ctx: PipelineContext) -> StepOutcome:
        if not getattr(ctx.settings, self.enabled_setting):
            return StepOutcome.ok(f"Шаг выключен настройкой ({self.enabled_setting.upper()}).")

        artifact = _current_artifact(ctx)
        if artifact is None:
            return StepOutcome.fail(
                "Артефакт для сканирования не найден — шаг скачивания не выполнен.",
                item_status="failed",
                version_status="failed",
                next_action="Перезапустите проверку заявки.",
            )

        payload = ctx.cache.get("artifact_payload")
        if payload is None:
            payload = get_object_storage().get(artifact.s3_key or "")
            ctx.cache["artifact_payload"] = payload

        limits = UnpackLimits(
            max_total_bytes=ctx.settings.scan_max_unpacked_bytes,
            max_files=ctx.settings.scan_max_files,
        )
        unpacked = unpack_artifact(payload, artifact.filename, limits=limits)
        try:
            outcome = self._scanner().scan(unpacked.root)
        except Exception as exc:  # noqa: BLE001 - сбой сканера не роняет конвейер
            log.exception("сканер содержимого упал", extra={"scanner": self.scanner_name})
            outcome = ScanOutcome(available=False, detail=f"сканер завершился ошибкой: {exc}")
        finally:
            cleanup(unpacked)

        _store_code_findings(ctx, outcome.findings, self.scanner_name)

        # Информационный шаг: вердикт ни на что не влияет, поэтому и решение
        # DevSecOps здесь ни при чём — ветка стоит до проверки override.
        if self.advisory:
            return self._advise(ctx, outcome)

        # Явное разрешение DevSecOps важнее вердикта шага. Без этой проверки
        # одобрение зацикливалось бы: конвейер возобновляется с шага скачивания,
        # сканер находит то же самое и снова блокирует публикацию.
        if ctx.version.security_override_at is not None:
            decided = ctx.session.get(User, ctx.version.security_override_by_id or 0)
            who = decided.display_name if decided else "DevSecOps"
            details: dict[str, object] = {"reason": "security_override", "decided_by": who}
            # «Разрешено вручную» и «сканер не отработал» — разные вещи.
            # Раньше эта ветка стояла ДО проверки outcome.available и всегда
            # сообщала число находок: неустановленный semgrep выглядел в
            # карточке как чистый пакет («Находок: 0»), хотя отчёт по тому же
            # пакету показывал четыре срабатывания.
            if not outcome.available:
                details["scanner_unavailable"] = outcome.detail
                verdict = (
                    f" ВНИМАНИЕ: проверка не выполнялась ({outcome.detail}), "
                    "поэтому отсутствие находок ничего не означает."
                )
            else:
                details["findings_total"] = len(outcome.findings)
                verdict = f" Находок: {len(outcome.findings)}."
            return StepOutcome.ok(
                f"{self.title}: публикация разрешена вручную ({who}).{verdict}",
                details=details,
            )

        if not outcome.available:
            # Недоступный сканер — не «чисто». Решает DevSecOps.
            return StepOutcome.pending(
                f"{self.title}: проверка не выполнена ({outcome.detail}). "
                "Автоматическое одобрение по этому шагу отключено.",
                details={"reason": "scanner_unavailable", "detail": outcome.detail},
                item_status="awaiting_security",
                version_status="awaiting_security",
                next_action=(
                    f"Дождитесь решения DevSecOps: {self.title.lower()} не отработал, "
                    "вердикт выносится вручную."
                ),
                notify_roles=["devsecops"],
                notify_event=Event.REQUEST_AWAITS_SECURITY,
            )

        threshold = self._min_severity(ctx)
        blocking = [
            f
            for f in outcome.findings
            if SEVERITY_ORDER.index(f.severity) >= SEVERITY_ORDER.index(threshold)
        ]
        if blocking:
            top = blocking[:20]
            summary = ", ".join(sorted({f.rule_id for f in top}))
            return StepOutcome.pending(
                f"{self.title}: найдено срабатываний — {len(blocking)} "
                f"(правила: {summary}). Требуется решение DevSecOps.",
                details={
                    "reason": "findings",
                    "count": len(blocking),
                    "threshold": threshold,
                    "findings": [f.to_dict() for f in top],
                    "unpacked_notes": unpacked.notes,
                },
                item_status="awaiting_security",
                version_status="awaiting_security",
                next_action="Посмотрите находки в карточке пакета — решение принимает DevSecOps.",
                notify_roles=["devsecops"],
                notify_event=Event.REQUEST_AWAITS_SECURITY,
            )

        note = f" Ниже порога: {len(outcome.findings)}." if outcome.findings else ""
        return StepOutcome.ok(
            f"{self.title}: срабатываний выше порога «{threshold}» нет. {outcome.detail}.{note}",
            details={"threshold": threshold, "detail": outcome.detail, "notes": unpacked.notes},
        )


class BannerScanStep(_ContentScanStep):
    code = "banner_scan"
    title = "Политические баннеры"
    scanner_name = "yara"
    enabled_setting = "banner_scan_enabled"

    def _scanner(self):
        return get_banner_scanner()

    def _min_severity(self, ctx: PipelineContext) -> str:
        # Баннер — находка сама по себе: порога здесь нет, любое совпадение
        # правила уходит DevSecOps.
        return "info"


class SastScanStep(_ContentScanStep):
    """SAST по исходникам пакета.

    Информационный шаг: публикацию не блокирует, нужен для отчёта. Причина в
    природе находок — semgrep на исходниках библиотеки размечает eval/exec,
    которые для половины пакетов нормальная работа, а не закладка. Блокирующий
    SAST означал бы ручное подтверждение каждого второго пакета, и
    подтверждение перестаёт быть решением. Политические баннеры — обратный
    случай: совпадение правила там само по себе повод не публиковать.
    """

    code = "sast_scan"
    title = "SAST-анализ"
    scanner_name = "semgrep"
    enabled_setting = "sast_enabled"
    advisory = True

    def _scanner(self):
        return get_sast_scanner()

    def _min_severity(self, ctx: PipelineContext) -> str:
        return ctx.settings.sast_min_severity


def _store_code_findings(ctx: PipelineContext, findings: list, scanner: str) -> None:
    """Перезаписывает находки этого сканера для версии пакета."""
    version = ctx.version
    for existing in [f for f in version.code_findings if f.scanner == scanner]:
        ctx.session.delete(existing)
    ctx.session.flush()
    for finding in findings[:500]:  # в карточке всё равно показываем верхушку
        ctx.session.add(
            CodeFinding(
                package_version_id=version.id,
                scanner=finding.scanner,
                rule_id=finding.rule_id,
                severity=finding.severity,
                message=finding.message,
                file_path=finding.file,
                line=finding.line,
                matched=finding.matched,
                detected_at=utcnow(),
            )
        )
    ctx.session.flush()


def _blocked_outcome(ctx: PipelineContext, blockers: list[str]) -> StepOutcome:
    """Публикация отложена: какое-то согласование ещё не получено.

    Роль и статус берутся из общих справочников в app/pipeline/blockers.py.
    Держать здесь свою копию нельзя: при добавлении шага она разъезжается с
    основной, и конвейер падает на неизвестном коде.
    """
    primary = blockers[0]
    status = BLOCKER_STATUS[primary]
    who = BLOCKER_WAITING_FOR[primary]
    role = BLOCKER_ROLE[primary]
    event = (
        Event.REQUEST_AWAITS_LEGAL
        if role == "legal"
        else Event.REQUEST_AWAITS_SECURITY
        if role == "devsecops"
        else Event.DECISION_MADE
    )
    names = ", ".join(STEP_TITLES[code] for code in blockers)
    return StepOutcome(
        result="warn",
        message=(
            f"Публикация отложена: не получено согласование по шагам — {names}. "
            f"Ожидается решение: {who}."
        ),
        details={"pending": blockers},
        stop=True,
        item_status=status,
        version_status=status,
        next_action=(
            f"Пакет проверен, но ждёт решения ({who}). "
            "Как только согласование будет получено, публикация пройдёт автоматически."
        ),
        notify_roles=[role] if role else [],
        notify_event=event,
    )


class PublishStep(PipelineStepHandler):
    code = "publish"
    title = "Выгрузка в артефактори"

    def run(self, ctx: PipelineContext) -> StepOutcome:
        # Согласования идут параллельно, поэтому к публикации пакет может прийти
        # с непогашенной блокировкой — например, уязвимости проверены, а лицензия
        # ещё у юриста. Публиковать в этом случае нельзя.
        blockers = pending_blockers(ctx.item)
        if blockers:
            return _blocked_outcome(ctx, blockers)

        artifact = _current_artifact(ctx)
        if artifact is None:
            return StepOutcome.fail(
                "Артефакт для публикации не найден.",
                item_status="failed",
                version_status="failed",
                next_action="Перезапустите проверку заявки.",
            )
        store = get_artifact_store()
        storage = get_object_storage()
        payload = ctx.cache.get("artifact_payload")
        if payload is None:
            payload = storage.get(artifact.s3_key or "")

        repo = ctx.settings.artifact_repo(ctx.package.manager)

        if ctx.settings.artifact_dry_run:
            # Весь конвейер выполняется по-настоящему (реальное скачивание,
            # реальные сканеры) — не публикуем в целевой артефактори реальными
            # байтами. Проверяем только достижимость/авторизацию (HEAD), чтобы
            # креды от реального Artifactory/Sandbox были проверены без риска
            # записи. См. docs/testing.md, "Тесты не пишут в целевой Artifactory".
            would_be_url = store.artifact_url(ctx.ref, artifact.filename)
            try:
                reachable = store.exists(ctx.ref, artifact.filename)
                auth_note = "артефактори отвечает, доступ подтверждён"
            except UpstreamError as exc:
                reachable = None
                auth_note = f"проверка достижимости не удалась: {exc.message}"
            command = ctx.plugin.install_command(ctx.ref, ctx.settings.artifact_base_url, repo)
            # Статус заявки/версии сознательно НЕ переводим в approved: публикации не
            # было, реального артефакта по install_command ещё нет.
            return StepOutcome(
                result="pass",
                message=(
                    f"[dry-run] Публикация пропущена (ARTIFACT_DRY_RUN=true). "
                    f"Был бы опубликован по {would_be_url}. {auth_note}."
                ),
                details={
                    "dry_run": True,
                    "would_be_url": would_be_url,
                    "already_exists": reachable,
                    "install_command_if_published": command,
                    "repo": repo,
                },
                terminal=True,
            )

        url = store.publish(ctx.ref, artifact.filename, payload)
        artifact.nexus_url = url
        artifact.published_at = utcnow()
        artifact.status = "published"

        # MinIO — временная зона: объект удаляется сразу после успешной выгрузки.
        purge_artifact(ctx, artifact, reason="Опубликован в артефактори", keep_status=True)

        command = ctx.plugin.install_command(ctx.ref, ctx.settings.artifact_base_url, repo)
        ctx.version.approved_at = utcnow()
        ctx.session.flush()
        return StepOutcome(
            result="pass",
            message=f"Пакет опубликован во внутреннем репозитории {repo}: {url}",
            details={"nexus_url": url, "install_command": command, "repo": repo},
            terminal=True,
            item_status="approved",
            version_status="approved",
            next_action=f"Устанавливайте из внутреннего репозитория: {command}",
            notify_event=Event.PACKAGE_APPROVED,
        )


def purge_artifact(
    ctx: PipelineContext, artifact: Artifact, *, reason: str, keep_status: bool = False
) -> None:
    """Удаляет объект из MinIO и фиксирует время удаления."""
    if artifact.s3_key and artifact.s3_deleted_at is None:
        get_object_storage().delete(artifact.s3_key)
        artifact.s3_deleted_at = utcnow()
        if not keep_status:
            artifact.status = "purged"
        log.info(
            "объект удалён из временного хранилища",
            extra={"key": artifact.s3_key, "reason": reason},
        )
    ctx.cache.pop("artifact_payload", None)
    ctx.session.flush()


def fetch_metadata_cached(ctx: PipelineContext):
    """Метаданные реестра запрашиваются один раз на прогон конвейера."""
    meta = ctx.cache.get("registry_metadata")
    if meta is None:
        meta = ctx.plugin.fetch_metadata(ctx.ref)
        ctx.cache["registry_metadata"] = meta
    return meta


STEP_HANDLERS: list[PipelineStepHandler] = [
    DbCheckStep(),
    BlacklistStep(),
    QuarantineStep(),
    LicenseStep(),
    DownloadStep(),
    VulnScanStep(),
    BannerScanStep(),
    SastScanStep(),
    PublishStep(),
]

HANDLERS_BY_CODE: dict[str, PipelineStepHandler] = {h.code: h for h in STEP_HANDLERS}
