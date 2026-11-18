# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS builder
WORKDIR /src
ARG VERSION=v4.0.0
ARG COMMIT=none

COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY tools ./tools

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -o /out/sonic ./cmd/sonic && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -o /out/sonic-mcp ./cmd/sonic-mcp

FROM alpine:3.20 AS runtime
RUN apk add --no-cache tshark ca-certificates && \
    addgroup -S sonic && adduser -S -G sonic sonic

COPY --from=builder /out/sonic /usr/local/bin/sonic
COPY --from=builder /out/sonic-mcp /usr/local/bin/sonic-mcp

USER sonic
WORKDIR /captures
ENTRYPOINT ["/usr/local/bin/sonic"]
