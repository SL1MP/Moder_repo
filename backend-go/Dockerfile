# syntax=docker/dockerfile:1

# --------------------------------------------------------------- сборка
FROM golang:1.25-alpine AS build

# Прокси на этапе сборки передаётся build-аргументами (в образ не попадает) —
# как в backend/Dockerfile. Без него `go mod download` не выйдет наружу в
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
 && apt-get install -y --no-install-recommends ca-certificates curl yara python3 python3-pip \
 && rm -rf /var/lib/apt/lists/*

# semgrep — шаг SAST. Ставится отдельно и НЕ фатально: без него шаг честно
# отдаёт «проверка не выполнена» и зовёт DevSecOps, а не притворяется, что
# чисто. Тот же приём, что в backend/Dockerfile.
RUN if [ "$INSTALL_SEMGREP" = "true" ]; then \
      pip install --no-cache-dir --break-system-packages semgrep \
      || echo "semgrep не установлен: шаг SAST будет требовать решения DevSecOps"; \
    fi

# Непривилегированный пользователь: сервис ничего не пишет на диск, кроме
# временных каталогов распаковки.
RUN useradd -u 10001 -m moderation
USER moderation

COPY --from=build /out/moderation /usr/local/bin/moderation

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/moderation"]
