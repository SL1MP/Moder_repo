# syntax=docker/dockerfile:1

# --------------------------------------------------------------- сборка
ARG SYFT_VERSION=v0.80.0
FROM golang:1.25-alpine AS build

# Прокси на этапе сборки передаётся build-аргументами (в образ не попадает) —
# как и для остальных сборочных стадий. Без него `go mod download` не выйдет наружу в
# корпоративной сети.
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

WORKDIR /src

# Зависимости отдельным слоем: правка кода не тянет за собой их перекачивание.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 — статический бинарник: в финальном образе не нужен ни libc,
# ни совпадение версий. -trimpath убирает пути сборочной машины,
# -s -w выкидывают отладочные таблицы (образ меньше почти вдвое).
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/moderation ./cmd/moderation

# Syft is copied from its official image rather than downloaded by curl during
# the build. The version is pinned because its CycloneDX shape is an API for
# downstream consumers.
FROM anchore/syft:${SYFT_VERSION} AS syft

# --------------------------------------------------------------- рантайм
# debian-slim, а не alpine: semgrep ставится через pip и официально musl не
# поддерживает. Go-бинарник статический, ему база безразлична.
FROM debian:12-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG INSTALL_SEMGREP=true

# yara — CLI для шага «Политические баннеры». В отличие от python-версии
# (там yara-python, cgo-биндинг) здесь используется тот же бинарь, что и для
# semgrep: два внешних сканера запускаются единообразно.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git skopeo yara python3 python3-pip \
 && rm -rf /var/lib/apt/lists/*

# semgrep — шаг SAST. Ставится отдельно и НЕ фатально: без него шаг честно
# отдаёт «проверка не выполнена» и зовёт DevSecOps, а не притворяется, что
# чисто. Пустые значения удаляются перед запуском сканеров.
RUN if [ "$INSTALL_SEMGREP" = "true" ]; then \
      pip install --no-cache-dir --break-system-packages semgrep \
      || echo "semgrep не установлен: шаг SAST будет требовать решения DevSecOps"; \
    fi

# Непривилегированный пользователь. Каталог OSV создаётся в образе заранее:
# при первом подключении пустого named volume Docker сохранит его владельца,
# и worker сможет атомарно менять /var/lib/osv-db/current без root.
RUN useradd -u 10001 -m moderation \
 && install -d -o moderation -g moderation /var/lib/osv-db
USER moderation

COPY --from=build /out/moderation /usr/local/bin/moderation
COPY --from=syft /syft /usr/local/bin/syft

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/moderation"]
