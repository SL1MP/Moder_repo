-- Шаг песочницы вместо снятых сканеров содержимого.
--
-- Что меняется по сути: конвейер больше не выполняет banner_scan (политические
-- баннеры, YARA) и sast_scan (semgrep) — решение пользователя «на данном этапе
-- пока убрать», — и выполняет новый шаг sandbox_scan: артефакт целиком
-- уходит во внешнюю песочницу, та запускает его и возвращает вердикт.
--
-- Коды снятых шагов из CHECK-ограничения НЕ убираются. Строки pipeline_step с
-- ними лежат в базе у каждой заявки, проверенной до этой миграции, и запрет на
-- значение сломал бы не будущие вставки, а чтение прошлого. Ровно поэтому в
-- коде рядом с domain.StepCodes появился domain.RetiredStepCodes, а здесь —
-- полный список из действующих и снятых кодов.
--
-- Список записан литералом намеренно: миграция — снимок состояния на своей
-- ревизии, и сторожевой тест сверяет литералы с константами в коде. Не
-- собирать в цикле — см. комментарий в 0004.
--
-- Два имени в DROP и IF EXISTS — не перестраховка: схему этой базы мог создать
-- любой из двух наборов миграций (golang-migrate называет ограничение
-- pipeline_step_step_code_check, Alembic — ck_pipeline_step_step_code). Снять
-- только своё значило бы оставить второе ограничение со старым списком, и
-- вставка sandbox_scan падала бы с CheckViolation — тот же способ, которым
-- коды banner_scan/sast_scan однажды уже доехали до прода сломанными.
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_step_code_check;
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_code;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_step_code_check CHECK (step_code IN (
    'db_check', 'blacklist', 'quarantine', 'license', 'download',
    'vuln_scan', 'sandbox_scan', 'publish',
    -- Снятые с конвейера, но живущие в истории:
    'banner_scan', 'sast_scan'
));

-- То же для отчётов: у scan_report свой CHECK на step_code (0005), и без него
-- первый же отчёт песочницы упал бы при вставке.
ALTER TABLE scan_report DROP CONSTRAINT IF EXISTS scan_report_step_code_check;
ALTER TABLE scan_report DROP CONSTRAINT IF EXISTS ck_scan_report_step_code;
ALTER TABLE scan_report ADD CONSTRAINT scan_report_step_code_check CHECK (step_code IN (
    'sandbox_scan', 'banner_scan', 'sast_scan'
));

-- Старые строки banner_scan с результатом warn: шаг больше не выполняется, и
-- «ждём решения DevSecOps» по нему — неправда, решения никто уже не примет.
-- Переводим в info, сохраняя сообщение прогона: оно и есть запись о находках.
--
-- Это ровно то, что миграция 0010 сделала для sast_scan. Без этого пакеты,
-- остановленные снятым шагом, висели бы в очереди DevSecOps вечно.
UPDATE pipeline_step SET result = 'info' WHERE step_code = 'banner_scan' AND result = 'warn';

-- Пакеты, которые ждали DevSecOps ТОЛЬКО из-за снятых шагов, возвращаем в
-- очередь конвейера с шага скачивания — так же, как это делает решение
-- DevSecOps (resume_from_step). Прогон пересчитает блокировки, выполнит новый
-- шаг песочницы и либо опубликует пакет, либо вернёт его в ожидание по той
-- причине, которая осталась.
--
-- Отбор строгий: пакет, который ждёт ещё и уязвимостей, лицензии или
-- карантина, остаётся на месте — его статус верен. Проверка по vuln_scan
-- учитывает оба открытых результата (warn и fail), по остальным — warn:
-- см. pipeline.OpenResults.
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
  );

-- Заявки, чьи пакеты только что вернулись в очередь, больше не «ждут
-- DevSecOps». Свёрнутый статус заявки пересчитает конвейер на первом же
-- прогоне, но до него заявка провисит со старым статусом, и в очереди
-- DevSecOps будет висеть строка без единого пакета в ожидании.
UPDATE moderation_request mr
SET status = 'pending', updated_at = now()
WHERE mr.status = 'awaiting_security'
  AND NOT EXISTS (
      SELECT 1 FROM request_item ri
      WHERE ri.request_id = mr.id AND ri.status = 'awaiting_security'
  );
