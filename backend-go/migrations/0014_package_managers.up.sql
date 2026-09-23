-- Полный набор пакетных менеджеров.
--
-- Было четыре (pypi, npm, go, nuget) — те, что перенёс прототип. Добавляются
-- восемь: conan, docker, luarocks, maven, php, terraform, git, files.
-- Поддержка всех видов модерации — обязательный скоуп сервиса, а не бэклог
-- (docs/ci-parity-gaps.md): пока менеджера нет, сервис не заменяет CI-версию
-- для тех, кто им пользуется.
--
-- Два последних кода стоят особняком и поэтому названы именно так:
--   git   — модерация git-репозитория целиком (не пакета из реестра);
--   files — модерация готового архива или двоичного файла, который разработчик
--           приносит сам: у него нет ни реестра, ни канонической версии.
--
-- VARCHAR(16) не трогаем: самый длинный новый код — terraform (9 символов).
--
-- Список записан литералом намеренно: миграция — снимок состояния на своей
-- ревизии, и сторожевой тест сверяет литералы с константами в коде
-- (domain.ManagerCodes). Не собирать в цикле — см. комментарий в 0004.
--
-- Два имени в DROP и IF EXISTS: схему базы мог создать любой из двух наборов
-- миграций (golang-migrate и Alembic называют ограничения по-разному), и
-- оставшееся чужое ограничение со старым списком отклоняло бы каждый пакет
-- нового менеджера — см. ту же историю в 0010 и 0013.
ALTER TABLE package DROP CONSTRAINT IF EXISTS package_manager_check;
ALTER TABLE package DROP CONSTRAINT IF EXISTS ck_package_manager;
-- Имя из alembic-набора (NAMING_CONVENTION): именно оно стоит на схеме,
-- созданной python-версией. Снимать надо оба — иначе старое запрещающее
-- ограничение остаётся рядом с новым разрешающим, и запись отвергается по нему.
ALTER TABLE package DROP CONSTRAINT IF EXISTS ck_package_manager_code;
ALTER TABLE package ADD CONSTRAINT package_manager_check CHECK (manager IN (
    'pypi', 'npm', 'go', 'nuget',
    'conan', 'docker', 'luarocks', 'maven', 'php', 'terraform',
    'git', 'files'
));

ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS moderation_request_manager_check;
ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS ck_moderation_request_manager;
ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS ck_moderation_request_manager_code;
ALTER TABLE moderation_request ADD CONSTRAINT moderation_request_manager_check CHECK (manager IN (
    'pypi', 'npm', 'go', 'nuget',
    'conan', 'docker', 'luarocks', 'maven', 'php', 'terraform',
    'git', 'files'
));

ALTER TABLE package_manager DROP CONSTRAINT IF EXISTS package_manager_code_check;
ALTER TABLE package_manager DROP CONSTRAINT IF EXISTS ck_package_manager_code;
ALTER TABLE package_manager DROP CONSTRAINT IF EXISTS ck_package_manager_manager_code;
ALTER TABLE package_manager ADD CONSTRAINT package_manager_code_check CHECK (code IN (
    'pypi', 'npm', 'go', 'nuget',
    'conan', 'docker', 'luarocks', 'maven', 'php', 'terraform',
    'git', 'files'
));

-- Справочник менеджеров для выпадающего списка в интерфейсе. Строки пишем
-- здесь, а не оставляем на bootstrap: справочник читает и python-версия, и
-- go-версия, и пустой он означает пустой список менеджеров на странице
-- заведения пакетов.
--
-- ON CONFLICT DO NOTHING, а не UPDATE: заголовок и формат записи
-- администратор мог поправить под себя, и миграция не вправе это затирать.
-- enabled=true у всех: менеджер, который выключать не просили, должен быть
-- доступен сразу после накатывания.
INSERT INTO package_manager (code, title, entry_format, enabled) VALUES
    ('maven',     'Maven',     'groupId:artifactId:version', true),
    ('docker',    'Docker',    'image:tag',                  true),
    ('conan',     'Conan',     'name/version',               true),
    ('luarocks',  'LuaRocks',  'rock version',               true),
    ('terraform', 'Terraform', 'namespace/name version',     true),
    ('php',       'PHP',       'vendor/package:version',     true),
    ('git',       'Git',       'url@ref',                    true),
    ('files',     'Файлы',     'url@sha256:<хеш>',           true)
ON CONFLICT (code) DO NOTHING;
