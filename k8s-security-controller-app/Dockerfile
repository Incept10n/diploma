FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k8s-security-controller .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/k8s-security-controller .

# Копируем конфигурационные файлы
#COPY config/ /config/

# Явно указываем точку входа и аргументы по умолчанию
ENTRYPOINT ["./k8s-security-controller"]
CMD ["--mode=controller"]
