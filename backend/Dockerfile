# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Прокси на этапе сборки передаётся build-аргументами (в образ не попадает).
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG OSV_SCANNER_VERSION=1.9.2

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates libpq5 \
 && rm -rf /var/lib/apt/lists/*

# osv-scanner используется на шаге 5 в offline-режиме по локальному снапшоту OSV.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) osv_arch=amd64 ;; arm64) osv_arch=arm64 ;; *) osv_arch="" ;; esac; \
    if [ -n "$osv_arch" ]; then \
      curl -fsSL -o /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${osv_arch}" \
      && chmod +x /usr/local/bin/osv-scanner \
      || echo "osv-scanner не установлен: будет использован прямой запрос к снапшоту OSV"; \
    fi

WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[dev]"

# semgrep — шаг 7 (SAST). Ставится отдельно от зависимостей приложения: пакет
# крупный, тянет своё дерево, и его отсутствие не должно ронять сборку образа.
# Шаг это переживает — при недоступном сканере пакет уходит DevSecOps, а не
# проходит молча (см. app/adapters/content_scan.py).
ARG INSTALL_SEMGREP=true
RUN if [ "$INSTALL_SEMGREP" = "true" ]; then       pip install --no-cache-dir semgrep       || echo "semgrep не установлен: шаг SAST будет требовать решения DevSecOps";     fi

COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Директория под распакованный снапшот OSV.
RUN mkdir -p /var/lib/osv-db \
 && groupadd -r app && useradd -r -g app -d /app app \
 && chown -R app:app /app /var/lib/osv-db
USER app

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["api"]
