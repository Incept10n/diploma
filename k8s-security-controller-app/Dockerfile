FROM golang:1.26-alpine AS builder

WORKDIR /app

ENV GOPROXY=https://proxy.golang.org,direct
ENV GO111MODULE=on

COPY go.mod go.sum ./

# Принудительный вывод с -x и отключением кэша
RUN set -x && \
    echo "=== Starting go mod download at $(date) ===" && \
    go mod download -x && \
    echo "=== Finished go mod download at $(date) ==="

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o k8s-security-controller .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/k8s-security-controller .

ENTRYPOINT ["./k8s-security-controller"]
CMD ["--mode=controller"]