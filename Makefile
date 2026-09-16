SHELL := /bin/bash
COMPOSE ?= docker compose
PROD := -f docker-compose.yml -f docker-compose.prod.yml
PROFILES ?= --profile nexus --profile sso

.DEFAULT_GOAL := help
.PHONY: help env up up-all down restart logs ps build bootstrap migrate revision \
        test test-fast lint fmt shell cli sync-osv rescan reload import-list run-pending \
        queue-status queue-doctor api-smoke certs wait-nexus check-dockerfiles sql \
        prod-up prod-down clean

help: ## Список команд
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	 | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

env: ## Создать .env из .env.example (не перезаписывает существующий)
	@test -f .env || (cp .env.example .env && echo ".env создан из .env.example — заполните секреты")
	@test -f .env && echo ".env на месте"

up: env ## Поднять сервис (внешние Nexus/Keycloak берутся из .env)
	$(COMPOSE) up -d --build
	@echo "UI: http://localhost:$${NGINX_PORT:-8080}  API-docs: http://localhost:$${NGINX_PORT:-8080}/api/docs"

up-all: env ## Поднять сервис вместе с Nexus и Keycloak (профили nexus, sso)
	$(COMPOSE) $(PROFILES) up -d --build

down: ## Остановить сервис
	$(COMPOSE) $(PROFILES) down

restart: ## Применить правки .env и config/ (пересоздаёт api/api-go/worker/beat)
	# Именно up -d, а не restart: переменные из env_file фиксируются при создании
	# контейнера, поэтому `docker compose restart` правки .env НЕ подхватывает.
	# api-go здесь обязателен: он читает тот же .env (OIDC_*, LOCAL_AUTH_*,
	# SCAN_*), и без пересоздания правки доступа применятся только к python-версии.
	$(COMPOSE) up -d api api-go worker beat

logs: ## Логи api, api-go, worker и beat
	$(COMPOSE) logs -f api api-go worker beat

ps: ## Состояние контейнеров
	$(COMPOSE) $(PROFILES) ps

build: ## Пересобрать образы
	$(COMPOSE) build

migrate: ## Применить миграции Alembic
	$(COMPOSE) run --rm api migrate

sql: ## Показать SQL миграций без применения: make sql [FROM=base TO=head]
	@# Рендер офлайн, база не нужна. Ловит ошибки уровня SQL — например,
	@# удвоенный префикс в имени ограничения, на котором миграция уже падала.
	$(COMPOSE) run --rm --entrypoint alembic api upgrade $(or $(FROM),base):$(or $(TO),head) --sql

revision: ## Новая миграция: make revision M="описание"
	$(COMPOSE) run --rm api cli --help >/dev/null
	$(COMPOSE) run --rm --entrypoint alembic api revision --autogenerate -m "$(M)"

bootstrap: ## Миграции, realm Keycloak, бакеты MinIO, репозитории Nexus, демо-данные
	@# Nexus готов через 1-3 минуты после старта. Без ожидания bootstrap падал
	@# на создании репозиториев, и его приходилось запускать повторно.
	@$(MAKE) --no-print-directory wait-nexus
	$(COMPOSE) run --rm api bootstrap --demo
	@bash scripts/bootstrap_keycloak.sh || echo "Keycloak: realm импортируется контейнером при старте (профиль sso)"
	@echo "bootstrap завершён"

certs: ## Самоподписанный сертификат для nginx и Keycloak: make certs DOMAIN=example.com
	@test -n "$(DOMAIN)" || (echo "Укажите домен: make certs DOMAIN=<имя хоста>" && exit 1)
	@mkdir -p certs nginx/certs keycloak/certs
	openssl req -x509 -newkey rsa:2048 -nodes \
	  -keyout certs/server.key -out certs/server.crt \
	  -days 825 -subj "/CN=$(DOMAIN)" \
	  -addext "subjectAltName=DNS:$(DOMAIN)"
	@# Docker не видит соседние каталоги из build-контекста, поэтому копии.
	@cp certs/server.crt certs/server.key nginx/certs/
	@cp certs/server.crt certs/server.key keycloak/certs/
	@echo "Сертификат готов. Пересоберите образы: make up-all ARGS=--build"
	@echo "Ключи в git не попадают (см. .gitignore)."

wait-nexus: ## Дождаться готовности Nexus (используется в bootstrap)
	@COMPOSE="$(COMPOSE)" bash scripts/wait-nexus.sh

import-list: ## Импорт package_list.txt: make import-list FILE=./package_list.txt MANAGER=pypi
	$(COMPOSE) run --rm -v "$(abspath $(FILE)):/tmp/list.txt:ro" api \
	  cli import-package-list /tmp/list.txt --manager $(MANAGER) --origin "$(FILE)"

sync-osv: ## Загрузить снапшот базы OSV из артефактори
	$(COMPOSE) run --rm api cli sync-osv

rescan: ## Перепроверить одобренные пакеты по текущему снапшоту
	$(COMPOSE) run --rm api cli rescan

reload: ## Перечитать blacklist и справочник лицензий
	$(COMPOSE) run --rm api cli reload-policies

run-pending: ## Прогнать застрявшие в очереди пакеты синхронно, не дожидаясь сторожа
	$(COMPOSE) run --rm api cli run-pending

queue-status: ## Кто разбирает очередь: жив ли worker, сколько пакетов зависло
	$(COMPOSE) run --rm api cli queue-status

queue-doctor: ## Разбор одной командой: почему пакеты стоят в очереди (вывод слать целиком)
	@# Ненулевой код возврата — это «нашлась проблема», а не сбой команды:
	@# в make он выглядел бы как `*** Error 1` поверх нормального отчёта.
	@$(COMPOSE) run --rm api cli queue-doctor || true

api-smoke: ## Прогон REST API: make api-smoke SVC_USER=ci-bot SVC_PASSWORD=... [PKG=six==1.16.0]
	./scripts/api-smoke.sh $(PKG)

cli: ## Произвольная команда CLI: make cli ARGS="--help"
	$(COMPOSE) run --rm api cli $(ARGS)

shell: ## Shell внутри контейнера api
	$(COMPOSE) run --rm --entrypoint bash api

test: ## Тесты с покрытием (порог 70%)
	$(COMPOSE) run --rm --entrypoint pytest api

test-fast: ## Тесты без покрытия
	$(COMPOSE) run --rm --entrypoint pytest api -q --no-cov

lint: ## Проверка стиля backend и frontend
	$(COMPOSE) run --rm --entrypoint ruff api check app tests
	cd frontend && npm run lint
	@$(MAKE) --no-print-directory check-dockerfiles

check-dockerfiles: ## Проверить Dockerfile'ы без сборки (ловит обрыв многострочных RUN)
	@python3 scripts/check-dockerfiles.py .

fmt: ## Автоформатирование backend
	$(COMPOSE) run --rm --entrypoint ruff api check --fix app tests

prod-up: ## Поднять в проде
	$(COMPOSE) $(PROD) up -d --build

prod-down: ## Остановить прод
	$(COMPOSE) $(PROD) down

clean: ## Удалить контейнеры и volume'ы (данные будут потеряны)
	$(COMPOSE) $(PROFILES) down -v
