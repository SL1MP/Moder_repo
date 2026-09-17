-- SAST — информационный шаг: результат `info` и разблокировка старых пакетов.
--
-- Политика: находки SAST нужны для отчёта, а не для запрета. semgrep на
-- исходниках библиотеки размечает eval/exec, которые для половины пакетов —
-- нормальная работа; блокирующий SAST означал бы, что DevSecOps подтверждает
-- каждый второй пакет, и подтверждение перестаёт быть решением. Политические
-- баннеры блокируют по-прежнему: там совпадение правила само по себе повод не
-- публиковать.
--
-- Новый результат шага `info` — «выполнен, публикацию не держит, но сказать
-- есть что». Отдельное значение, а не pass: «пройден» рядом с четырьмя
-- находками читается как «чисто», и именно это уже вводило в заблуждение.
--
-- Список записан литералом намеренно — см. комментарий в 0004.
-- Два имени в DROP — не перестраховка. Схему этой базы мог создать любой из
-- двух наборов миграций: golang-migrate называет ограничение
-- `pipeline_step_result_check`, Alembic (python-версия) — по своему
-- соглашению `ck_pipeline_step_step_result`. Если снять только своё, на базе
-- из другого набора осталось бы второе ограничение со старым списком, и
-- вставка `info` падала бы с CheckViolation — ровно тот способ, которым коды
-- banner_scan/sast_scan однажды уже дошли до прода сломанными.
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_result_check;
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_result;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_result_check CHECK (result IN (
    'pending', 'pass', 'info', 'warn', 'fail', 'skipped'
));

-- Старые строки sast_scan с результатом warn: шаг больше не блокирующий, и
-- «остановка» в карточке по нему — неправда. Переводим в info, сохраняя
-- сообщение прогона: оно и есть запись о находках.
UPDATE pipeline_step SET result = 'info' WHERE step_code = 'sast_scan' AND result = 'warn';

-- Пакеты, которые ждали DevSecOps ТОЛЬКО из-за SAST, ждут решения, которого
-- больше не существует: в очереди DevSecOps они висели бы вечно. Возвращаем
-- их в очередь конвейера с шага скачивания — так же, как это делает решение
-- DevSecOps (resume_from_step). Прогон пересчитает блокировки и либо
-- опубликует пакет, либо вернёт его в ожидание по той причине, которая
-- осталась.
--
-- Отбор строгий: только пакеты без других непогашенных проверок. Пакет,
-- который ждёт ещё и уязвимостей, баннеров, лицензии или карантина, остаётся
-- на месте — его статус верен.
UPDATE request_item ri
SET status = 'queued', resume_from_step = 'download', updated_at = now()
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
          OR (ps.step_code IN ('banner_scan', 'license', 'quarantine') AND ps.result = 'warn'))
  );
