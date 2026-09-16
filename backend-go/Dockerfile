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
FROM alpine:3.20

# ca-certificates нужны для похода в реестры пакетных менеджеров и артефактори
# по HTTPS. wget уже есть в busybox — им делается healthcheck.
RUN apk add --no-cache ca-certificates

# Непривилегированный пользователь: сервис ничего не пишет на диск, кроме
# временных каталогов распаковки.
RUN adduser -D -u 10001 moderation
USER moderation

COPY --from=build /out/moderation /usr/local/bin/moderation

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/moderation"]
