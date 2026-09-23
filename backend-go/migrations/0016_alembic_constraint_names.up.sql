-- Снятие CHECK-ограничений, уцелевших от alembic-набора.
--
-- Миграция 0014 снимала не те имена. У схемы, созданной alembic'ом, имена
-- строятся его соглашением (NAMING_CONVENTION в backend/app/db/base.py), и для
-- менеджеров они такие:
--
--     package            -> ck_package_manager_code
--     moderation_request -> ck_moderation_request_manager_code
--     package_manager    -> ck_package_manager_manager_code
--
-- А 0014 снимала ck_package_manager, ck_moderation_request_manager и
-- ck_package_manager_code (последнее — с package_manager, где его нет вовсе:
-- это имя принадлежит таблице package).
--
-- Последствие коварное: миграция проходит УСПЕШНО. Новое разрешающее
-- ограничение добавляется, старое запрещающее остаётся рядом, и запись
-- отвергается по нему. Снаружи это «миграции накатились, а менеджеры всё
-- равно не работают»; `moderation schema` при этом честно показывает, что
-- значение не разрешено, и называет уже накатанную миграцию.
--
-- Почему отдельной миграцией, а не правкой 0014: на стендах, где 0014 уже
-- записана применённой, исправленная версия не выполнится никогда. 0014
-- тоже поправлена — для установок с alembic-базы, которым она ещё предстоит.
--
-- На схеме, созданной go-набором, эта миграция не делает ничего: перечисленных
-- имён там нет, а ограничения уже правильные.

ALTER TABLE package DROP CONSTRAINT IF EXISTS ck_package_manager_code;
ALTER TABLE package DROP CONSTRAINT IF EXISTS package_manager_check;
ALTER TABLE package ADD CONSTRAINT package_manager_check CHECK (manager IN (
    'pypi', 'npm', 'go', 'nuget',
    'conan', 'docker', 'luarocks', 'maven', 'php', 'terraform',
    'git', 'files'
));

ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS ck_moderation_request_manager_code;
ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS moderation_request_manager_check;
ALTER TABLE moderation_request ADD CONSTRAINT moderation_request_manager_check CHECK (manager IN (
    'pypi', 'npm', 'go', 'nuget',
    'conan', 'docker', 'luarocks', 'maven', 'php', 'terraform',
    'git', 'files'
));

ALTER TABLE package_manager DROP CONSTRAINT IF EXISTS ck_package_manager_manager_code;
ALTER TABLE package_manager DROP CONSTRAINT IF EXISTS package_manager_code_check;
ALTER TABLE package_manager ADD CONSTRAINT package_manager_code_check CHECK (code IN (
    'pypi', 'npm', 'go', 'nuget',
    'conan', 'docker', 'luarocks', 'maven', 'php', 'terraform',
    'git', 'files'
));
