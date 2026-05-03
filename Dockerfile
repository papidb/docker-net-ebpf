FROM --platform=$BUILDPLATFORM golang:1.24-bookworm AS builder

ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-libc-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETARCH
ENV GOARCH=$TARGETARCH
ENV CGO_ENABLED=0

RUN go generate ./internal/collector/ebpf/...
RUN go build -trimpath -ldflags="-s -w" -o /netwatch ./cmd/docker-net-ebpf

FROM gcr.io/distroless/static-debian12

COPY --from=builder /netwatch /netwatch

ENTRYPOINT ["/netwatch"]
CMD ["watch"]
