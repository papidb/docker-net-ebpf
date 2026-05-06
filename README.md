# docker-net-ebpf

Per-container network observability using eBPF. Tracks which containers are talking to which IPs and how much data they're moving — directly from the Linux kernel.

```
kernel (cgroup_skb) → eBPF map → Go userspace → you
```

## Quick Start

### Docker Compose (easiest)

```bash
docker compose -f docker-compose.lab.yml up --build
```

This brings up a demo lab with traffic-generating containers and `netwatch` observing them. Open `http://localhost:9090` for Prometheus.

### Docker (observer only)

```bash
docker compose up
```

### From Source

```bash
go generate ./internal/collector/ebpf/...
go build -o docker-net-ebpf ./cmd/docker-net-ebpf
sudo ./docker-net-ebpf doctor
sudo ./docker-net-ebpf watch
```

Requires Go 1.25+, clang, llvm, libbpf-dev, linux-libc-dev on Linux.

## Commands

```bash
sudo docker-net-ebpf doctor                          # check environment readiness
sudo docker-net-ebpf watch                            # live terminal view
sudo docker-net-ebpf watch console prometheus :9099   # live view + prometheus
sudo docker-net-ebpf record                           # record to JSONL (default)
sudo docker-net-ebpf record jsonl sqlite              # record to both
```

Most commands need `sudo` because they load eBPF programs and attach to cgroups.

## Outputs

Multiple outputs can run simultaneously:

| Output | Description | Default destination |
|--------|-------------|---------------------|
| `console` | Live terminal table | — |
| `jsonl` | Append-only JSON lines | `output/traffic.jsonl` |
| `sqlite` | SQLite database | `output/traffic.db` |
| `prometheus` | `/metrics` HTTP endpoint | `:9099` |

```bash
sudo docker-net-ebpf record jsonl ./traffic.jsonl sqlite ./traffic.db prometheus :8080
```

Output guides:

- [Outputs overview](docs/outputs/README.md)
- [Console output](docs/outputs/console.md)
- [JSONL output](docs/outputs/jsonl.md)
- [SQLite output](docs/outputs/sqlite.md)
- [Prometheus output](docs/outputs/prometheus.md)

## Platform Support

| Platform | Status |
|----------|--------|
| Linux hosts | Supported |
| OrbStack on macOS | Experimental (observes the VM kernel) |
| Docker Desktop (macOS/Windows) | Experimental |

This tool always observes a Linux kernel. On macOS, that's the VM kernel, not the host.

## How It Works

eBPF programs attach to each container's cgroup and count bytes/packets per remote IP on every packet — no polling, no sampling, no Docker API overhead. A Go binary reads the counters periodically and pipes them through four stages:

```
Collector → Resolver → Aggregator → Output(s)
```

See [docs/architecture.md](docs/architecture.md) for the full breakdown with diagrams.

## Documentation

- [Architecture](docs/architecture.md) — how the system works behind the scenes
- [Outputs overview](docs/outputs/README.md) — how to combine and configure outputs
- [Console output](docs/outputs/console.md) — live terminal behavior
- [JSONL output](docs/outputs/jsonl.md) — append-only file output
- [SQLite output](docs/outputs/sqlite.md) — local queryable history
- [Prometheus output](docs/outputs/prometheus.md) — metrics, scrape config, and useful PromQL

## Project Structure

```
bpf/                        eBPF C programs
cmd/docker-net-ebpf/        CLI entrypoint (Cobra)
internal/
  aggregator/simple/        delta computation
  collector/ebpf/           eBPF map reader + generated bindings
  doctor/                   environment preflight checks
  output/{console,jsonl,sqlite,prometheus,fanout}/
  resolver/docker/          Docker Engine API → container info
netwatch/                   shared interfaces and data types
scripts/                    BPF code generation wrapper
docs/                       architecture and output guides
```

## License

See [LICENSE](LICENSE).
