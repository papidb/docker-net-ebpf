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

## Quick Start (Docker)

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

> **Platform support:** Linux only. Docker Desktop (macOS/Windows) runs a LinuxKit VM — eBPF will attach inside the VM, not on your host. Use a Linux VM or cloud instance for real results.

## Build from Source

Requires Go 1.25+, clang, llvm, libbpf-dev, linux-libc-dev.

```bash
go generate ./internal/collector/ebpf/...
go build -o netwatch .
sudo ./netwatch
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

The eBPF collector and cgroup attachment work. `main.go` now wires four explicit stages together using the `netwatch` interfaces, while still keeping a simple synchronous loop and console output by default.

What exists:
- eBPF program with per-CPU hash map (working)
- Docker container discovery via `docker ps` + cgroup walk
- `netwatch.Collector`, `Resolver`, `Aggregator`, and `Output` interfaces
- Concrete Docker resolver, eBPF collector, simple aggregator, and console output wiring in `main.go`
- Cumulative counter display in terminal
- Destination-aware sample model and console view for IPv4/TCP traffic by remote IP

What's defined but not yet implemented:
- Delta-based aggregation and counter reset handling
- Proper Linux-side regeneration of BPF bindings after the IPv4/TCP destination key change (`go generate ./...` must be run on Linux with kernel headers and `llvm-strip` available)
- UDP and IPv6 destination tracking
- `netwatch.Output` interface (JSONL, SQLite, Prometheus, Kafka)

## Project Structure

```
├── bpf/
│   └── netwatch.bpf.c          # eBPF cgroup_skb programs
├── internal/
│   ├── aggregator/simple/       # Simple aggregator implementation
│   ├── collector/ebpf/          # eBPF collector + generated bindings
│   ├── output/console/          # Console output implementation
│   └── resolver/docker/         # Docker resolver implementation
├── netwatch/
│   ├── types.go                 # RawTrafficSample, TrafficSample, ContainerInfo
│   └── interfaces.go            # Collector, Resolver, Aggregator, Output
├── main.go                      # Thin pipeline orchestration
├── Dockerfile                   # Multi-stage build (clang + Go → distroless)
├── docker-compose.yml           # Privileged sidecar config
└── go.mod
```

## Roadmap

- [x] Extract collector, resolver, aggregator, and console output into interface-based pipeline wiring
- [ ] Delta computation and counter reset handling
- [x] Docker image with multi-stage build (BPF compilation + distroless runtime)
- [x] Docker Compose sidecar config
- [ ] JSONL output
- [ ] SQLite output with time-range queries
- [ ] Prometheus metrics exporter
- [ ] containerd resolver (Kubernetes pod support)
- [ ] Extend destination-level visibility beyond IPv4/TCP (UDP, IPv6, DNS/service enrichment, optional port breakdown)
