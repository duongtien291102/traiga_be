# Multi-stage Dockerfile cho Golang Backend
FROM golang:alpine AS builder

WORKDIR /app

# Cho phép Go tự động nâng toolchain nếu go.mod yêu cầu phiên bản cao hơn
ENV GOTOOLCHAIN=auto

# Cài đặt git và ca-certificates (cần cho việc tải package và HTTPS requests)
RUN apk add --no-cache git ca-certificates

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy mã nguồn
COPY . .

# Biên dịch binary tĩnh (CGO_ENABLED=0)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/livestream-be ./cmd/server

# Runtime image siêu nhẹ
FROM alpine:3.20

WORKDIR /app

# Cài đặt tzdata cho múi giờ và ca-certificates cho kết nối HTTPS / Mongo Atlas
RUN apk --no-cache add ca-certificates tzdata

COPY --from=builder /app/livestream-be /app/livestream-be

# Expose cổng API và WebSocket
EXPOSE 8000

CMD ["/app/livestream-be"]
