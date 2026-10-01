-- Вердикт внешней песочницы является результатом проверки сам по себе.
-- DANGEROUS может прийти без массива detections, поэтому восстановить его из
-- findings_total невозможно: храним рядом со сводкой отчёта.
ALTER TABLE scan_report
    ADD COLUMN IF NOT EXISTS verdict VARCHAR(32);
