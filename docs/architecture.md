# Architecture

## The Problem

```
 "Network spiked on the VM. Which container caused it?"
```

Docker stats has no history. cAdvisor loses container-level attribution.
Prometheus requires prior setup. Logs are too noisy.

This tool answers the question directly from the Linux kernel.

## High-Level Flow

```
┌─────────────────────────────────────────────────────────────┐
│                        Linux Kernel                         │
│                                                             │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│   │ cgroup A │  │ cgroup B │  │ cgroup C │  ...             │
│   │(lab-web) │  │(lab-egr) │  │(lab-int) │                  │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘                  │
│        │              │              │                      │
│   ┌────▼──────────────▼──────────────▼────┐                 │
│   │         cgroup_skb/ingress            │  eBPF programs  │
│   │         cgroup_skb/egress             │  (per cgroup)   │
│   └────────────────┬──────────────────────┘                 │
│                    │                                        │
│   ┌────────────────▼──────────────────────┐                 │
│   │     BPF_MAP_TYPE_PERCPU_HASH          │                 │
│   │                                       │                 │
│   │  key: cgroup_id + remote_ip4          │                 │
│   │       + direction + protocol          │                 │
│   │                                       │                 │
│   │  value: bytes (cumulative)            │                 │
│   │         packets (cumulative)          │                 │
│   └────────────────┬──────────────────────┘                 │
└────────────────────┼────────────────────────────────────────┘
                     │
          ╔══════════▼══════════╗
          ║   Go Userspace      ║
          ║   (every 2 seconds) ║
          ╚══════════╤══════════╝
                     │
         ┌───────────▼───────────┐
         │       Collector       │
         │                       │
         │  reads per-CPU map    │
         │  sums per-CPU values  │
         │ emits RawTrafficSample│
         └───────────┬───────────┘
                     │
         ┌───────────▼───────────┐
         │       Resolver        │
         │                       │
         │  cgroup_id ──► name   │
         │  Docker socket API    │
         └───────────┬───────────┘
                     │
         ┌───────────▼───────────┐
         │      Aggregator       │
         │                       │
         │  cumulative ──► delta │
         │  fold RX + TX rows    │
         │  detect counter reset │
         │  emit TrafficSample   │
         └───────────┬───────────┘
                     │
         ┌───────────▼───────────┐
         │      Output(s)        │
         │                       │
         │  ┌─────────────────┐  │
         │  │ Console (table) │  │
         │  │ JSONL (file)    │  │
         │  │ SQLite (db)     │  │
         │  │ Prom. (http)    │  │
         │  └─────────────────┘  │
         └───────────────────────┘
```

## What Happens on Every Packet

```
 Container sends/receives a packet
              │
              ▼
 ┌──────────────────────────┐
 │  cgroup_skb hook fires   │
 │  (ingress or egress)     │
 └────────────┬─────────────┘
              │
              ▼
 ┌──────────────────────────┐
 │  Parse IPv4 header       │
 │  Extract:                │
 │    - remote IP           │
 │    - protocol (TCP/UDP)  │
 │    - direction           │
 │    - cgroup_id (from skb)│
 └────────────┬─────────────┘
              │
              ▼
 ┌──────────────────────────┐
 │  Lookup key in map       │
 │  If missing: create      │
 │  Increment:              │
 │    bytes  += skb->len    │
 │    packets += 1          │
 └──────────────────────────┘
```

No copies. No userspace involvement. Pure in-kernel accounting.

## The eBPF Map Key

```
struct traffic_key {
    cgroup_id    u64     ──► which container
    remote_ip4   u32     ──► talking to whom
    direction    u8      ──► ingress (0) or egress (1)
    protocol     u8      ──► TCP (6) or UDP (17)
    pad          u16     ──► alignment
}
```

This means the kernel tracks a separate counter for every unique combination of:

```
(container, remote IP, direction, protocol)
```

The map is `PERCPU_HASH` — each CPU has its own copy, avoiding lock contention.
Userspace sums the per-CPU values on read.

## The Collection Loop

```
main.go owns a simple ticker loop:

    every 2 seconds:

    ┌─────────────────────────────────────────────┐
    │                                             │
    │  1. collector.Collect()                     │
    │     read all map entries                    │
    │     sum per-CPU values                      │
    │     emit []RawTrafficSample                 │
    │                                             │
    │  2. aggregator.Aggregate()                  │
    │     compare with previous snapshot          │
    │     compute deltas (bytes, packets)         │
    │     fold ingress/egress into one row        │
    │     emit []TrafficSample                    │
    │                                             │
    │  3. output.Write()                          │
    │     fan out to all configured outputs       │
    │     console: clear + print table            │
    │     jsonl: append JSON lines                │
    │     sqlite: INSERT rows                     │
    │     prometheus: replace latest snapshot     │
    │                                             │
    └─────────────────────────────────────────────┘
```

No goroutine pipelines. No channels. One loop, four stages, in sequence.

## Delta Computation

The eBPF counters are cumulative — they only go up. The aggregator
turns them into deltas by remembering the previous value for each key.

```
  poll 1:  bytes = 1000          ──► delta = 0     (first sample)
  poll 2:  bytes = 1500          ──► delta = 500
  poll 3:  bytes = 2300          ──► delta = 800
  poll 4:  bytes = 100           ──► delta = 100   (reset detected)
```

Rules:
- First sample for a key: delta = 0 (no baseline)
- Normal: delta = current - previous
- Counter decrease: treated as reset, delta = current value
- Reset() clears all previous state

The aggregator also folds ingress and egress into a single output row:

```
  Raw:
    (lab-egress, 1.2.3.4, ingress, tcp) ──► RX fields
    (lab-egress, 1.2.3.4, egress,  tcp) ──► TX fields

  Output:
    lab-egress  1.2.3.4  tcp  RX=...  TX=...
```

## Container Discovery

```
  ┌────────────────┐       ┌──────────────────────┐
  │ Docker         │       │  /sys/fs/cgroup      │
  │ Engine API     │       │                      │
  │                │       │  system.slice/       │
  │ GET /containers│       │   docker-<id>.scope  │
  │                │       │                      │
  └──────┬─────────┘       └──────────┬───────────┘
         │                            │
         │  container ID              │  cgroup path
         │  container name            │  cgroup inode (= cgroup_id)
         │                            │
         └──────────┬─────────────────┘
                    │
                    ▼
              ContainerInfo {
                  ID:         "abc123..."
                  Name:       "lab-egress"
                  CgroupID:   12345
                  CgroupPath: "/sys/fs/cgroup/system.slice/docker-abc123.scope"
                  Runtime:    "docker"
              }
```

The resolver talks to Docker over `/var/run/docker.sock`. No CLI dependency.
It walks `/sys/fs/cgroup` to find each container's cgroup path, then gets the
inode number which the kernel uses as `cgroup_id` in BPF.

## eBPF Attachment

```
  For each discovered container:

  ┌──────────────────────────────────────┐
  │  open cgroup directory fd            │
  │  /sys/fs/cgroup/.../docker-<id>.scope│
  └──────────────┬───────────────────────┘
                 │
  ┌──────────────▼───────────────────────┐
  │  link = AttachCgroup(fd, program)    │
  │                                      │
  │  attach count_ingress to cgroup      │
  │  attach count_egress  to cgroup      │
  └──────────────────────────────────────┘
```

Two BPF programs per container. One counts ingress, one counts egress.
Both write to the same shared map.

## Output Pipeline

Multiple outputs run simultaneously through a fanout:

```
                 TrafficSample[]
                       │
              ┌────────▼────────┐
              │     Fanout      │
              │                 │
              │  for each output│
              │    output.Write │
              └─┬─────┬─────┬───┘
                │     │     │
       ┌────────▼┐ ┌──▼────┐ ┌▼──────────┐
       │ Console │ │ JSONL │ │ SQLite    │ ...
       │         │ │       │ │           │
       │ table   │ │ append│ │ INSERT    │
       │ to      │ │ to    │ │ into      │
       │ terminal│ │ file  │ │ database  │
       └─────────┘ └───────┘ └───────────┘
```

Prometheus is different — it holds the latest snapshot in memory and
serves it when Prometheus scrapes `/metrics`:

```
       ┌──────────────────────┐
       │  Prometheus Output   │
       │                      │
       │  Write() ──► store   │     ┌──────────┐
       │  latest snapshot     │◄────│ GET      │
       │                      │     │ /metrics │
       │  Collect() ──► serve │────►│          │
       │  on scrape           │     └──────────┘
       └──────────────────────┘
```

## Project Layout

```
docker-net-ebpf/
│
├── bpf/
│   └── netwatch.bpf.c              kernel-side eBPF programs
│
├── cmd/
│   └── docker-net-ebpf/
│       └── main.go                  CLI (Cobra), collection loop
│
├── internal/
│   ├── aggregator/simple/           delta computation
│   ├── collector/ebpf/              map reader + generated bindings
│   ├── doctor/                      environment preflight checks
│   ├── output/
│   │   ├── console/                 terminal table
│   │   ├── fanout/                  multi-output splitter
│   │   ├── jsonl/                   JSON lines file
│   │   ├── prometheus/              /metrics HTTP endpoint
│   │   └── sqlite/                  SQLite database
│   └── resolver/docker/             Docker socket ──► container info
│
├── netwatch/
│   ├── types.go                     shared data model
│   └── interfaces.go                Collector, Resolver, Aggregator, Output
│
├── scripts/
│   └── generate-bpf.sh             portable BPF code generation
│
├── docs/
│   ├── architecture.md              this file
│   └── outputs/
│       └── prometheus.md            Prometheus query reference
│
├── Dockerfile                       multi-stage build (clang + go + distroless)
├── docker-compose.yml               observer-only
└── docker-compose.lab.yml           full demo lab + Prometheus
```

## Why cgroup_skb?

There are several eBPF hook points for network observability:

```
Hook              Granularity     Container-aware?    Overhead
─────────────────────────────────────────────────────────────
tc (traffic ctrl)    per-veth        manual mapping      low
XDP                  per-NIC         no                  lowest
kprobe/tracepoint    per-function    manual              variable
socket filters       per-socket      manual              low
cgroup_skb           per-cgroup      yes, native         low
```

`cgroup_skb` is the right choice because:

- **Native container attribution** — the kernel maps packets to cgroups automatically
- **No veth chasing** — no need to discover and attach to virtual interfaces
- **Both directions** — ingress and egress hooks on the same cgroup
- **skb access** — full packet headers available for destination extraction

The tradeoff: only sees traffic that enters or leaves the cgroup boundary.
Traffic between processes in the same cgroup is invisible (but that's rarely
what you care about for container observability).

## Limitations

- **IPv4 + TCP/UDP only** — IPv6 and other protocols are silently ignored
- **No port tracking** — destinations are IP-level, not IP:port
- **Maps not pinned** — eBPF map resets on process restart
- **Static discovery** — containers must be running at startup
- **Linux only** — macOS/Windows see the VM kernel, not the host
