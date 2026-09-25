-- Откат намеренно обрезает только отображаемое имя сканера: старое состояние
-- схемы физически не способно хранить более длинное значение.
ALTER TABLE scan_report
    ALTER COLUMN scanner TYPE VARCHAR(32)
    USING LEFT(scanner, 32);
