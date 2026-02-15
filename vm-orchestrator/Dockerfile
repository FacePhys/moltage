# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

COPY go.mod ./
RUN go mod tidy
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /orchestrator ./cmd/orchestrator

# Production stage
FROM alpine:3.19

RUN apk add --no-cache \
    iptables \
    iproute2 \
    e2fsprogs \
    coreutils \
    ca-certificates

# Firecracker binary must be provided via volume or copied during deployment
# COPY --from=firecracker /firecracker /usr/local/bin/firecracker

COPY --from=builder /orchestrator /usr/local/bin/orchestrator

# Create required directories
RUN mkdir -p /var/lib/firecracker/vms \
    /var/lib/firecracker/rootfs \
    /tmp/firecracker/sockets

ENV PORT=8080
ENV HOST=0.0.0.0

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/orchestrator"]
