-- Возвращает тип, существовавший до 0017. После такого отката Go-версия не
-- должна обслуживать уведомления, поскольку её запросы требуют jsonb.

ALTER TABLE "user"
    ALTER COLUMN roles TYPE json
    USING roles::json;
