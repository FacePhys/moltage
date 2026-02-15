# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY go.mod ./
RUN go mod tidy
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /ssh-gateway ./cmd/gateway

# Production stage
FROM alpine:3.19
RUN apk add --no-cache ca-certificates openssh-keygen

COPY --from=builder /ssh-gateway /usr/local/bin/ssh-gateway

# Host key storage
RUN mkdir -p /etc/ssh-gateway

ENV LISTEN_ADDR=0.0.0.0:2222
ENV HOST_KEY_PATH=/etc/ssh-gateway/host_key
ENV VM_SSH_USER=user
ENV VM_SSH_PASS=clawdbot

EXPOSE 2222

ENTRYPOINT ["/usr/local/bin/ssh-gateway"]
