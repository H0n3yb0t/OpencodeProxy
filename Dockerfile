FROM node:22-alpine AS web-build
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/opencodeproxy ./cmd/opencodeproxy

FROM alpine:3.22
LABEL org.opencontainers.image.title="OpencodeProxy" \
      org.opencontainers.image.source="https://github.com/H0n3yb0t/OpencodeProxy" \
      org.opencontainers.image.description="OpenCode Go failover proxy and key pool"
RUN apk add --no-cache ca-certificates tzdata && addgroup -S opencodeproxy && adduser -S -G opencodeproxy -h /app opencodeproxy
WORKDIR /app
COPY --from=go-build /out/opencodeproxy /app/opencodeproxy
COPY --from=web-build /src/web/dist /app/web
RUN mkdir -p /data && chown opencodeproxy:opencodeproxy /data /app
USER opencodeproxy
ENV LISTEN_ADDR=0.0.0.0:8080 DATABASE_PATH=/data/opencodeproxy.db INSTANCE_PATH=/data/instance.json WEB_DIR=/app/web
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/health/ready || exit 1
ENTRYPOINT ["/app/opencodeproxy"]
