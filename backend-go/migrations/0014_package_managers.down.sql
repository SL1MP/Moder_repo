-- Откат: вернуть четыре менеджера прототипа.
--
-- Пакеты новых менеджеров удаляются, а не остаются нарушать ограничение:
-- откат миграции, добавившей значение, обязан оставить базу в состоянии, куда
-- это значение не пролезает. Удаление каскадное по внешним ключам
-- (package_version → request_item → pipeline_step), поэтому вместе с пакетом
-- уходит и история его проверок — это и есть цена отката, и умолчать о ней
-- нельзя.
DELETE FROM moderation_request WHERE manager NOT IN ('pypi', 'npm', 'go', 'nuget');
DELETE FROM package WHERE manager NOT IN ('pypi', 'npm', 'go', 'nuget');
DELETE FROM package_manager WHERE code NOT IN ('pypi', 'npm', 'go', 'nuget');

ALTER TABLE package DROP CONSTRAINT IF EXISTS package_manager_check;
ALTER TABLE package DROP CONSTRAINT IF EXISTS ck_package_manager;
ALTER TABLE package ADD CONSTRAINT package_manager_check
    CHECK (manager IN ('pypi', 'npm', 'go', 'nuget'));

ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS moderation_request_manager_check;
ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS ck_moderation_request_manager;
ALTER TABLE moderation_request ADD CONSTRAINT moderation_request_manager_check
    CHECK (manager IN ('pypi', 'npm', 'go', 'nuget'));

ALTER TABLE package_manager DROP CONSTRAINT IF EXISTS package_manager_code_check;
ALTER TABLE package_manager DROP CONSTRAINT IF EXISTS ck_package_manager_code;
ALTER TABLE package_manager ADD CONSTRAINT package_manager_code_check
    CHECK (code IN ('pypi', 'npm', 'go', 'nuget'));
