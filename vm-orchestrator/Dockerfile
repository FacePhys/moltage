# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

ENV GOPROXY=https://goproxy.cn,direct

WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o /orchestrator ./cmd/orchestrator

# Production stage
FROM alpine:3.19

RUN apk add --no-cache \
    ca-certificates \
    iptables \
    iproute2 \
    bridge-utils \
    curl \
    e2fsprogs \
    bash

COPY --from=builder /orchestrator /usr/local/bin/orchestrator

# Download Firecracker binary
ARG TARGETARCH
RUN ARCH=$(uname -m) && \
    echo "Downloading Firecracker v1.6.0 for ${ARCH}..." && \
    curl -fSL "https://github.com/firecracker-microvm/firecracker/releases/download/v1.6.0/firecracker-v1.6.0-${ARCH}.tgz" \
      -o /tmp/firecracker.tgz && \
    tar xzf /tmp/firecracker.tgz -C /tmp && \
    mv /tmp/release-v1.6.0-${ARCH}/firecracker-v1.6.0-${ARCH} /usr/local/bin/firecracker && \
    chmod +x /usr/local/bin/firecracker && \
    rm -rf /tmp/firecracker.tgz /tmp/release-v1.6.0-*

# Download compatible Linux kernel (5.10, CI-tested with Firecracker v1.6.0)
RUN ARCH=$(uname -m) && \
    echo "Downloading vmlinux kernel for Firecracker v1.6.0..." && \
    mkdir -p /var/lib/firecracker && \
    curl -fSL "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.6/${ARCH}/vmlinux-5.10.217" \
      -o /var/lib/firecracker/vmlinux

# Firecracker directories
RUN mkdir -p /var/lib/firecracker/rootfs \
    /var/lib/firecracker/vms \
    /tmp/firecracker/sockets

# Copy entrypoint and setup scripts
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY scripts/setup-network.sh /usr/local/bin/setup-network.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/setup-network.sh

ENV PORT=8080

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
