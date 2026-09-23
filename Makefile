SHELL := /bin/bash
COMPOSE ?= docker compose
PROD := -f docker-compose.yml -f docker-compose.prod.yml
PROFILES ?= --profile nexus --profile sso

.DEFAULT_GOAL := help
.PHONY: help env up up-all down restart logs ps build bootstrap migrate migrate-status schema \
        test lint fmt shell cli sync-osv rescan quarantine import-list run-pending \
        service-account api-smoke certs wait-nexus check-dockerfiles \
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

restart: ## Применить правки .env и config/ (пересоздаёт api-go и worker-go)
	# Именно up -d, а не restart: переменные из env_file фиксируются при создании
	# контейнера, поэтому `docker compose restart` правки .env НЕ подхватывает.
	$(COMPOSE) up -d api-go worker-go

logs: ## Логи api-go и worker-go
	$(COMPOSE) logs -f api-go worker-go

ps: ## Состояние контейнеров
	$(COMPOSE) $(PROFILES) ps

build: ## Пересобрать образы
	$(COMPOSE) build

migrate: ## Применить миграции
	$(COMPOSE) run --rm migrate-go

migrate-status: ## Что применено, а что нет
	$(COMPOSE) run --rm api-go migrate --status

schema: ## Сверить схему базы с тем, что пишет код
	$(COMPOSE) run --rm api-go schema

bootstrap: ## Справочники, проверка репозиториев артефактори, демо-данные
	@# Nexus готов через 1-3 минуты после старта. Без ожидания проверка
	@# репозиториев показывала бы их отсутствующими.
	@$(MAKE) --no-print-directory wait-nexus
	$(COMPOSE) run --rm migrate-go
	$(COMPOSE) run --rm api-go bootstrap --demo
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
	$(COMPOSE) run --rm -v "$(abspath $(FILE)):/tmp/list.txt:ro" api-go \
	  import-packages /tmp/list.txt --manager $(MANAGER) --origin "$(FILE)"

sync-osv: ## Загрузить снапшот базы OSV
	$(COMPOSE) run --rm worker-go maintenance --osv-sync

rescan: ## Перепроверить одобренные пакеты по текущему снапшоту
	$(COMPOSE) run --rm worker-go maintenance --rescan

quarantine: ## Снять истёкший карантин
	$(COMPOSE) run --rm worker-go maintenance --quarantine

run-pending: ## Разобрать очередь синхронно, не дожидаясь сторожа
	$(COMPOSE) run --rm worker-go worker --once

service-account: ## Сервисная учётка для CI: make service-account USER=ci.gitlab ROLES=developer
	@# Пароль — через MODERATION_SERVICE_PASSWORD или стандартный ввод: значение
	@# флага видно в `ps` любому пользователю машины.
	$(COMPOSE) run --rm -e MODERATION_SERVICE_PASSWORD api-go \
	  service-account $(USER) --roles $(or $(ROLES),developer)

api-smoke: ## Прогон REST API: make api-smoke SVC_USER=ci-bot SVC_PASSWORD=... [PKG=six==1.16.0]
	./scripts/api-smoke.sh $(PKG)

cli: ## Произвольная команда CLI: make cli ARGS="--help"
	$(COMPOSE) run --rm api-go $(ARGS)

shell: ## Shell внутри контейнера api-go
	$(COMPOSE) run --rm --entrypoint sh api-go

test: ## Тесты go-версии (нужен MODERATION_TEST_POSTGRES_DSN — см. docs/testing.md)
	cd backend-go && go test -p 1 ./...

lint: ## Проверка стиля backend и frontend
	cd backend-go && gofmt -l . && go vet ./...
	cd frontend && npm run lint
	@$(MAKE) --no-print-directory check-dockerfiles

check-dockerfiles: ## Проверить Dockerfile'ы без сборки (ловит обрыв многострочных RUN)
	@python3 scripts/check-dockerfiles.py .

fmt: ## Автоформатирование backend
	cd backend-go && gofmt -w .

prod-up: ## Поднять в проде
	$(COMPOSE) $(PROD) up -d --build

prod-down: ## Остановить прод
	$(COMPOSE) $(PROD) down

clean: ## Удалить контейнеры и volume'ы (данные будут потеряны)
	$(COMPOSE) $(PROFILES) down -v
