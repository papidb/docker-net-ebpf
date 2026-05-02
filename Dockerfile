FROM --platform=$BUILDPLATFORM golang:1.24-bookworm AS builder

ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-libc-dev \
    && rm -rf /var/lib/apt/lists/* \
    && ARCH=$(uname -m) \
    && ln -sf /usr/include/${ARCH}-linux-gnu/asm /usr/include/asm

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETARCH
ENV GOARCH=$TARGETARCH
ENV CGO_ENABLED=0

RUN go generate ./internal/collector/ebpf/...
RUN go build -trimpath -ldflags="-s -w" -o /netwatch .

FROM alpine:3.22

RUN apk add --no-cache docker-cli

COPY --from=builder /netwatch /netwatch

ENTRYPOINT ["/netwatch"]
