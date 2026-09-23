-- Откат возвращает ограничения к четырём исходным менеджерам.
--
-- Имена при этом остаются go-набора: восстанавливать alembic-имена незачем,
-- обе версии сервиса читают ограничение, а не его имя, и следующая накатка
-- 0016 снимет оба варианта.
--
-- Строки с менеджерами, которых в списке нет, придётся убрать до отката:
-- ограничение проверяет существующие данные. Это осознанно — молча удалять
-- заявки ради отката миграции нельзя.

ALTER TABLE package DROP CONSTRAINT IF EXISTS package_manager_check;
ALTER TABLE package ADD CONSTRAINT package_manager_check CHECK (manager IN (
    'pypi', 'npm', 'go', 'nuget'
));

ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS moderation_request_manager_check;
ALTER TABLE moderation_request ADD CONSTRAINT moderation_request_manager_check CHECK (manager IN (
    'pypi', 'npm', 'go', 'nuget'
));

ALTER TABLE package_manager DROP CONSTRAINT IF EXISTS package_manager_code_check;
ALTER TABLE package_manager ADD CONSTRAINT package_manager_code_check CHECK (code IN (
    'pypi', 'npm', 'go', 'nuget'
));
