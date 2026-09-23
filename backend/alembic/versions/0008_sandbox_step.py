"""Шаг песочницы вместо снятых сканеров содержимого

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-23 10:00:00.000000+00:00

Конвейер больше не выполняет banner_scan (политические баннеры, YARA) и
sast_scan (semgrep) — решение пользователя «на данном этапе пока убрать», — и
выполняет новый шаг sandbox_scan: артефакт целиком уходит во внешнюю песочницу,
та запускает его и возвращает вердикт (CLEAN / UNWANTED / DANGEROUS).

Коды снятых шагов из CHECK-ограничения НЕ убираются. Строки pipeline_step с ними
лежат в базе у каждой заявки, проверенной до этой миграции, и запрет на значение
сломал бы не будущие вставки, а чтение прошлого.

Парная миграция golang-migrate — backend-go/migrations/0013_sandbox_step.
Держать обе обязательно: боевую базу может создавать любой из двух наборов, а
CHECK в ней — единственная защита от вставки неизвестного значения. Имена
ограничения у наборов разные, поэтому снимаются оба.

Список значений записан литералом намеренно — см. комментарий в 0004.
"""
from __future__ import annotations

from alembic import op

revision: str = '0008'
down_revision: str | None = '0007'
branch_labels: str | None = None
depends_on: str | None = None


def _drop_step_code() -> None:
    """Снимает ограничение, как бы его ни назвал создавший базу набор миграций."""
    op.execute("ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_code")
    op.execute("ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_step_code_check")


def _drop_report_step_code() -> None:
    op.execute("ALTER TABLE scan_report DROP CONSTRAINT IF EXISTS ck_scan_report_step_code")
    op.execute("ALTER TABLE scan_report DROP CONSTRAINT IF EXISTS scan_report_step_code_check")


def upgrade() -> None:
    _drop_step_code()
    op.create_check_constraint(
        'step_code',
        'pipeline_step',
        "step_code IN ('db_check', 'blacklist', 'quarantine', 'license', 'download', "
        "'vuln_scan', 'sandbox_scan', 'publish', 'banner_scan', 'sast_scan')",
    )

    # У отчётов свой CHECK на step_code (0005 go-набора): без него первый же
    # отчёт песочницы упал бы при вставке.
    _drop_report_step_code()
    op.create_check_constraint(
        'step_code',
        'scan_report',
        "step_code IN ('sandbox_scan', 'banner_scan', 'sast_scan')",
    )

    # Старые строки banner_scan с результатом warn: шаг больше не выполняется,
    # и «ждём решения DevSecOps» по нему — неправда, решения никто не примет.
    # Сообщение прогона сохраняем: оно и есть запись о находках.
    op.execute(
        "UPDATE pipeline_step SET result = 'info' "
        "WHERE step_code = 'banner_scan' AND result = 'warn'"
    )

    # Пакеты, которые ждали DevSecOps ТОЛЬКО из-за снятых шагов, возвращаем в
    # очередь конвейера с шага скачивания — так же, как это делает решение
    # DevSecOps. Отбор строгий: пакет, ждущий ещё и уязвимостей, лицензии или
    # карантина, остаётся на месте — его статус верен.
    op.execute(
        """
        UPDATE request_item ri
        SET status = 'queued', resume_from_step = 'download', updated_at = now()
        WHERE ri.status = 'awaiting_security'
          AND EXISTS (
              SELECT 1 FROM pipeline_step ps
              WHERE ps.request_item_id = ri.id
                AND ps.step_code IN ('banner_scan', 'sast_scan')
          )
          AND NOT EXISTS (
              SELECT 1 FROM pipeline_step ps
              WHERE ps.request_item_id = ri.id
                AND ((ps.step_code = 'vuln_scan' AND ps.result IN ('warn', 'fail'))
                  OR (ps.step_code IN ('license', 'quarantine') AND ps.result = 'warn'))
          )
        """
    )

    # Заявки, чьи пакеты только что вернулись в очередь, больше не «ждут
    # DevSecOps»: иначе в очереди висела бы строка без единого пакета в ожидании.
    op.execute(
        """
        UPDATE moderation_request mr
        SET status = 'pending', updated_at = now()
        WHERE mr.status = 'awaiting_security'
          AND NOT EXISTS (
              SELECT 1 FROM request_item ri
              WHERE ri.request_id = mr.id AND ri.status = 'awaiting_security'
          )
        """
    )


def downgrade() -> None:
    # Строки sandbox_scan удаляются, а не остаются нарушать ограничение: откат
    # миграции, добавившей значение, обязан оставить базу в состоянии, куда это
    # значение не пролезает.
    #
    # Что откат НЕ делает: не возвращает результат warn строкам banner_scan и не
    # возвращает пакеты в awaiting_security. Прежнее значение нигде не
    # сохранено, а угадывать по «info у banner_scan» нельзя: info там мог стоять
    # и до миграции.
    op.execute("DELETE FROM scan_report WHERE step_code = 'sandbox_scan'")
    op.execute("DELETE FROM pipeline_step WHERE step_code = 'sandbox_scan'")

    _drop_report_step_code()
    op.create_check_constraint(
        'step_code',
        'scan_report',
        "step_code IN ('banner_scan', 'sast_scan')",
    )

    _drop_step_code()
    op.create_check_constraint(
        'step_code',
        'pipeline_step',
        "step_code IN ('db_check', 'blacklist', 'quarantine', 'license', 'download', "
        "'vuln_scan', 'banner_scan', 'sast_scan', 'publish')",
    )
