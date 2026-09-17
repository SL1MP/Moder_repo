"""Результат шага info: SAST стал информационным

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-17 09:10:00.000000+00:00

SAST больше не блокирует публикацию: находки semgrep нужны для отчёта, а не
для запрета. Причина в природе находок — eval/exec в исходниках библиотеки для
половины пакетов нормальная работа, и блокирующий SAST означал бы ручное
подтверждение каждого второго пакета.

Отсюда новый результат шага `info` — «выполнен, публикацию не держит, но
сказать есть что». Отдельное значение, а не `pass`: «пройден» рядом с четырьмя
находками читается как «чисто», и именно это уже вводило в заблуждение.

Парная миграция golang-migrate — backend-go/migrations/0010_sast_advisory.
Держать обе обязательно: боевую базу может создавать любой из двух наборов, а
CHECK в ней — единственная защита от вставки неизвестного значения. Имена
ограничения у наборов разные, поэтому снимаются оба.

Список значений записан литералом намеренно — см. комментарий в 0004.
"""
from __future__ import annotations

from alembic import op

revision: str = '0005'
down_revision: str | None = '0004'
branch_labels: str | None = None
depends_on: str | None = None

def _drop_both_names() -> None:
    """Снимает ограничение, как бы его ни назвал создавший базу набор миграций."""
    op.execute("ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_result")
    op.execute("ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_result_check")


def upgrade() -> None:
    _drop_both_names()
    # Список литералом в самом вызове, а не через константу: миграции сверяются
    # с кодом разбором текста (tests/unit/test_migration_constraints.py), и
    # значение, спрятанное в переменную, этой сверкой не видно.
    op.create_check_constraint(
        'step_result',
        'pipeline_step',
        "result IN ('pending', 'pass', 'info', 'warn', 'fail', 'skipped')",
    )

    # Старые строки sast_scan с результатом warn: шаг больше не блокирующий, и
    # «остановка» в карточке по нему — неправда. Сообщение прогона сохраняем:
    # оно и есть запись о находках.
    op.execute("UPDATE pipeline_step SET result = 'info' "
               "WHERE step_code = 'sast_scan' AND result = 'warn'")

    # Пакеты, которые ждали DevSecOps ТОЛЬКО из-за SAST, ждут решения, которого
    # больше не существует: в очереди DevSecOps они висели бы вечно. Возвращаем
    # их в очередь конвейера — прогон пересчитает блокировки и либо опубликует
    # пакет, либо вернёт его в ожидание по той причине, которая осталась.
    #
    # Отбор строгий: только пакеты без других непогашенных проверок.
    op.execute("""
        UPDATE request_item ri
        SET status = 'queued', updated_at = now()
        WHERE ri.status = 'awaiting_security'
          AND EXISTS (
              SELECT 1 FROM pipeline_step ps
              WHERE ps.request_item_id = ri.id AND ps.step_code = 'sast_scan'
                AND ps.result = 'info'
          )
          AND NOT EXISTS (
              SELECT 1 FROM pipeline_step ps
              WHERE ps.request_item_id = ri.id
                AND ((ps.step_code = 'vuln_scan' AND ps.result IN ('warn', 'fail'))
                  OR (ps.step_code IN ('banner_scan', 'license', 'quarantine')
                      AND ps.result = 'warn'))
          )
    """)


def downgrade() -> None:
    # Значения info переводим назад в warn: другого «шаг не пройден» в прежней
    # схеме нет. Пакеты, которые upgrade вернул в очередь, обратно не
    # отправляются — они к этому моменту уже обработаны.
    op.execute("UPDATE pipeline_step SET result = 'warn' WHERE result = 'info'")
    _drop_both_names()
    op.create_check_constraint(
        'step_result',
        'pipeline_step',
        "result IN ('pending', 'pass', 'warn', 'fail', 'skipped')",
    )
