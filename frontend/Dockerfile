# syntax=docker/dockerfile:1
FROM node:22-alpine AS build

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund

COPY tsconfig.json vite.config.ts index.html ./
COPY src ./src
RUN npm run build

# Готовая сборка копируется в общий volume, откуда её отдаёт nginx.
FROM alpine:3.20
WORKDIR /app
COPY --from=build /app/dist ./dist
CMD ["sh", "-c", "cp -r /app/dist/* /output/ && echo 'SPA собрана'"]
