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
- Go 1.25+, clang (for building)

## Usage

Generate eBPF bindings and build:

```bash
go generate ./...
go build -o netwatch .
sudo ./netwatch
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
| Aggregator | Compute deltas from cumulative counters, derive rates | `netwatch.Aggregator`  |
| Output     | Write processed samples to a sink                     | `netwatch.Output`      |

Interfaces and data types live in the `netwatch/` package. See `netwatch/interfaces.go` and `netwatch/types.go`.

### Data Flow

```
RawTrafficSample (cumulative bytes/packets per cgroup+direction)
        ↓ Aggregator
TrafficSample (deltas, rates, resolved container identity)
        ↓ Output
sink (terminal, JSONL, SQLite, Prometheus, ...)
```

### eBPF Program

`bpf/netwatch.bpf.c` — two `cgroup_skb` programs (`count_ingress`, `count_egress`) that increment per-CPU hash map entries keyed by `(cgroup_id, direction)`.

## Current State

The eBPF collector and cgroup attachment work. The current `main.go` is a monolith that does collection, resolution, and terminal output inline. No delta computation, no pluggable outputs.

What exists:
- eBPF program with per-CPU hash map (working)
- Docker container discovery via `docker ps` + cgroup walk
- Cumulative counter display in terminal

What's defined but not yet implemented:
- `netwatch.Collector` interface
- `netwatch.Resolver` interface (Docker, containerd, Kubernetes)
- `netwatch.Aggregator` interface (delta computation, counter reset handling)
- `netwatch.Output` interface (JSONL, SQLite, Prometheus, Kafka)

## Project Structure

```
├── bpf/
│   └── netwatch.bpf.c          # eBPF cgroup_skb programs
├── netwatch/
│   ├── types.go                 # RawTrafficSample, TrafficSample, ContainerInfo
│   └── interfaces.go            # Collector, Resolver, Aggregator, Output
├── main.go                      # Monolith (to be refactored)
├── netwatch_bpfel.go            # Generated eBPF bindings (little-endian)
├── netwatch_bpfeb.go            # Generated eBPF bindings (big-endian)
└── go.mod
```

## Roadmap

- [ ] Extract collector, resolver, aggregator from main.go into interface implementations
- [ ] Delta computation and counter reset handling
- [ ] JSONL output
- [ ] SQLite output with time-range queries
- [ ] Prometheus metrics exporter
- [ ] containerd resolver (Kubernetes pod support)
- [ ] Destination-level visibility (container → IP → port → bytes)
