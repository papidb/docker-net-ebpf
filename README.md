# docker-net-ebpf

Per-container network usage tracking via eBPF cgroup_skb programs. Answers "which container used how much network (RX/TX)?" using kernel-level counters instead of Docker stats or cAdvisor.

## How It Works

```
kernel (cgroup_skb) → eBPF map → Go userspace → table output
```

eBPF programs attach to each container's cgroup and count bytes/packets on ingress and egress. A Go binary reads the per-CPU hash map every 2 seconds and prints a sorted table.

## Requirements

- Linux with eBPF and cgroupv2 support
- Root privileges
- Docker (for container discovery)

## Privilege Model

Most host-side commands need elevated privileges because they load eBPF programs, attach to cgroups, inspect kernel filesystems, and usually need access to the Docker socket.

- Use `sudo` for local CLI commands such as `doctor`, `watch`, `record`, and the planned `serve` command.
- Use `--privileged` (or the equivalent capability and mount set) for the containerized Docker / Compose flows.

Examples:

```bash
sudo docker-net-ebpf doctor
sudo docker-net-ebpf watch
sudo docker-net-ebpf record
docker compose up
docker compose -f docker-compose.lab.yml up --build
```

If you run without elevation, the most common failures are:
- `permission denied` on `/var/run/docker.sock`
- `operation not permitted` while creating eBPF maps or attaching programs
- missing capabilities such as `CAP_BPF`, `CAP_PERFMON`, or `CAP_SYS_ADMIN`

## Quick Start (Docker)

For a plain observer container:

```bash
docker compose up
```

## Demo Lab (Docker Compose)

Bring up a self-contained traffic lab plus `netwatch`:

```bash
docker compose -f docker-compose.lab.yml up --build
```

This starts:
- `lab-egress` → repeated Cloudflare downloads
- `lab-internal` → repeated HTTP calls to `lab-web`
- `netwatch` → privileged observer attached to the host Docker engine

Use this when you want a reproducible demo without the Lima-only helper script.

To stop the demo:

```bash
docker compose -f docker-compose.lab.yml down
```

Or run directly:

```bash
docker run --rm --privileged \
  --pid=host \
  --network=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  netwatch
```

## Platform Support

- **Linux hosts:** supported
- **OrbStack on macOS:** experimental, but the Compose demo flow has been tested successfully
- **Docker Desktop on macOS/Windows:** experimental at best; eBPF attaches inside the Linux VM, not to the native host OS

This project always observes a Linux kernel. On macOS that means the Linux VM provided by OrbStack, Docker Desktop, or Lima — not the macOS host network stack itself.

## Build from Source

Requires Go 1.25+, clang, llvm, libbpf-dev, linux-libc-dev.

```bash
go generate ./internal/collector/ebpf/...
go build -o docker-net-ebpf ./cmd/docker-net-ebpf
sudo ./docker-net-ebpf doctor
sudo ./docker-net-ebpf watch
sudo ./docker-net-ebpf record
```

`go generate` now goes through `scripts/generate-bpf.sh`.

Why that wrapper exists:
- `bpf2go` needs both the generic Linux headers and the **arch-specific** include directory
- on Debian/Ubuntu-style systems, `asm/types.h` usually lives under a triplet path such as:
  - `/usr/include/x86_64-linux-gnu`
  - `/usr/include/aarch64-linux-gnu`
- different environments (native Linux, Lima, Docker builder) expose those paths differently

The wrapper script detects the correct arch include directory and passes it to `clang`, so `go generate` works without relying on a manual `/usr/include/asm` symlink hack.

If generation still fails on Linux, make sure the distro headers are installed:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-libc-dev gcc
```

Or build via Docker:

```bash
docker build -t netwatch .
```

Output:

```
Docker network usage from eBPF cgroup_skb
----------------------------------------------------------------------------------------------------
CONTAINER                      ID              RX              TX              TOTAL
----------------------------------------------------------------------------------------------------
lab-egress                     a1b2c3d4e5f6    1.2GiB          5.2GiB          6.4GiB
lab-worker                     f6e5d4c3b2a1    200.0MiB        1.3GiB          1.5GiB
```

## Architecture

```
Collector → Resolver → Aggregator → Output
```

| Layer      | Responsibility                                        | Interface              |
|------------|-------------------------------------------------------|------------------------|
| Collector  | Attach eBPF programs to cgroups, read counters        | `netwatch.Collector`   |
| Resolver   | Map cgroup IDs to container names via runtime APIs    | `netwatch.Resolver`    |
| Aggregator | Normalize cumulative counters into container or destination totals | `netwatch.Aggregator`  |
| Output     | Write processed samples to a sink                     | `netwatch.Output`      |

Interfaces and data types live in the `netwatch/` package. See `netwatch/interfaces.go` and `netwatch/types.go`.

### Data Flow

```
RawTrafficSample (cumulative bytes/packets per cgroup+direction+remote IP)
        ↓ Aggregator
TrafficSample (resolved container identity + remote IP + current totals)
        ↓ Output
sink (terminal, JSONL, SQLite, Prometheus, ...)
```

### eBPF Program

`bpf/netwatch.bpf.c` — two `cgroup_skb` programs (`count_ingress`, `count_egress`) that increment per-CPU hash map entries keyed by `(cgroup_id, remote_ip4, direction, protocol)` for the current IPv4/TCP MVP.

## Current State

The eBPF collector and cgroup attachment work. `cmd/docker-net-ebpf/main.go` now wires four explicit stages together using the `netwatch` interfaces, while still keeping a simple synchronous loop and console output by default.

What exists:
- eBPF program with per-CPU hash map (working)
- Docker container discovery via Docker Engine API + cgroup walk
- `netwatch.Collector`, `Resolver`, `Aggregator`, and `Output` interfaces
- Concrete Docker resolver, eBPF collector, simple aggregator, and console output
- CLI entrypoint at `cmd/docker-net-ebpf/` with `doctor`, `watch`, and `record` commands
- Cumulative counter display in terminal
- Destination-aware sample model and console view for IPv4/TCP traffic by remote IP
- `doctor` command checking kernel, privileges, cgroup v2, bpffs, BTF, Docker socket, and eBPF attach ability
- JSONL and SQLite outputs behind `netwatch.Output`, including multi-output fanout

What's defined but not yet implemented:
- Delta-based aggregation and counter reset handling
- Proper Linux-side regeneration of BPF bindings after the IPv4/TCP destination key change (`go generate ./...` must be run on Linux with kernel headers and `llvm-strip` available)
- UDP and IPv6 destination tracking
- Additional `netwatch.Output` implementations (Prometheus, Kafka)

## Project Structure

```
├── cmd/
│   └── docker-net-ebpf/         # CLI entrypoint (doctor, watch, record)
│       └── main.go
├── bpf/
│   └── netwatch.bpf.c           # eBPF cgroup_skb programs
├── internal/
│   ├── aggregator/simple/        # Simple aggregator implementation
│   ├── collector/ebpf/           # eBPF collector + generated bindings
│   ├── doctor/                   # Environment preflight checks
│   ├── output/console/           # Console output implementation
│   ├── output/fanout/            # Multi-output fanout implementation
│   ├── output/jsonl/             # JSONL output implementation
│   ├── output/sqlite/            # SQLite output implementation
│   └── resolver/docker/          # Docker resolver (Engine API over socket)
├── netwatch/
│   ├── types.go                  # RawTrafficSample, TrafficSample, ContainerInfo
│   └── interfaces.go             # Collector, Resolver, Aggregator, Output
├── scripts/
│   └── generate-bpf.sh           # Portable BPF codegen wrapper
├── Dockerfile                    # Multi-stage build (clang + Go → distroless)
├── docker-compose.yml            # Privileged sidecar config
├── docker-compose.lab.yml        # Full demo lab with traffic generators
└── go.mod
```

## CLI Product Shape

```
docker-net-ebpf doctor     # preflight environment checks
docker-net-ebpf watch      # live terminal view of container network traffic
docker-net-ebpf record     # write samples to JSONL/SQLite with the same interval-driven loop
docker-net-ebpf top        # query recorded data for a time range
docker-net-ebpf serve      # expose Prometheus/OpenTelemetry endpoints
```

Example usage:

```bash
sudo docker-net-ebpf doctor
sudo docker-net-ebpf watch
sudo docker-net-ebpf record
sudo docker-net-ebpf record jsonl ./net.jsonl sqlite ./net.db
docker-net-ebpf top --from "2026-05-01T18:00:00Z" --to "2026-05-01T22:00:00Z"
sudo docker-net-ebpf serve --prometheus.addr :9099
```

The CLI wires things together. The real logic lives in `internal/` and `netwatch/`, independent of the CLI framework.

## Roadmap

- [x] Extract collector, resolver, aggregator, and console output into interface-based pipeline wiring
- [x] Docker image with multi-stage build (BPF compilation + distroless runtime)
- [x] Docker Compose sidecar config
- [x] Docker Compose demo lab with traffic generators
- [x] Docker Engine API resolver (removed docker-cli runtime dependency)
- [x] `doctor` command — environment preflight checks
- [x] `watch` command — live terminal view (formerly the default behavior)
- [x] CLI framework (Cobra) with proper command parsing
- [ ] Delta computation and counter reset handling
- [x] `record` command — write samples to JSONL/SQLite
- [ ] `top` command — query recorded data for a time range
- [ ] `serve` command — Prometheus/OpenTelemetry metrics endpoint
- [x] JSONL output
- [x] SQLite output with time-range queries
- [ ] Prometheus metrics exporter
- [ ] containerd resolver (Kubernetes pod support)
- [ ] Extend destination-level visibility beyond IPv4/TCP (UDP, IPv6, DNS/service enrichment, optional port breakdown)
- [ ] Kubernetes DaemonSet deployment
