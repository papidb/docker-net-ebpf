# Prometheus Output

## Setup

Add `prometheus` as an output to any command:

```bash
sudo docker-net-ebpf watch console prometheus
sudo docker-net-ebpf watch console prometheus :8080
sudo docker-net-ebpf record jsonl prometheus :9099
```

Default listen address: `:9099`

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `netwatch_rx_bytes_total` | counter | Total received bytes |
| `netwatch_tx_bytes_total` | counter | Total transmitted bytes |
| `netwatch_rx_packets_total` | counter | Total received packets |
| `netwatch_tx_packets_total` | counter | Total transmitted packets |

### Labels

| Label | Description |
|-------|-------------|
| `container` | Container name |
| `container_id` | Short container ID (12 chars) |
| `remote_ip` | Remote IP address |
| `protocol` | Network protocol (`tcp`, `udp`, `unknown`) |

## Scrape Config

Minimal `prometheus.yml`:

```yaml
global:
  scrape_interval: 5s

scrape_configs:
  - job_name: netwatch
    static_configs:
      - targets: ["localhost:9099"]
```

## Useful Queries

### Traffic Volume

```promql
# Top containers by total bytes sent
topk(5, sum by (container) (netwatch_tx_bytes_total))

# Top containers by total bytes received
topk(5, sum by (container) (netwatch_rx_bytes_total))

# Combined RX+TX per container
topk(5, sum by (container) (netwatch_rx_bytes_total + netwatch_tx_bytes_total))
```

### Rates (bytes/sec)

```promql
# TX rate per container
sum by (container) (rate(netwatch_tx_bytes_total[1m]))

# RX rate per container
sum by (container) (rate(netwatch_rx_bytes_total[1m]))

# Which container is currently sending the most
topk(3, sum by (container) (rate(netwatch_tx_bytes_total[1m])))
```

### Destination Analysis

```promql
# Where is a specific container sending traffic?
sort_desc(netwatch_tx_bytes_total{container="lab-egress"})

# Top remote IPs by received bytes across all containers
topk(10, sum by (remote_ip) (netwatch_rx_bytes_total))

# Internal traffic only (Docker bridge)
sum by (container) (netwatch_tx_bytes_total{remote_ip=~"192\\.168\\..*"})

# External traffic only (exclude Docker bridge and DNS)
sum by (container, remote_ip) (netwatch_tx_bytes_total{remote_ip!~"192\\.168\\..*|127\\.0\\.0\\..*"})
```

### Protocol Breakdown

```promql
# TCP vs UDP per container
sum by (container, protocol) (netwatch_rx_bytes_total)

# DNS traffic (UDP to Docker embedded DNS)
netwatch_tx_bytes_total{remote_ip="127.0.0.11", protocol="udp"}
```

### Spike Detection

```promql
# Containers with TX rate > 1MB/s in last 5 minutes
sum by (container) (rate(netwatch_tx_bytes_total[5m])) > 1e6

# Sudden spikes: current 1m rate vs 5m average (ratio > 2 = spike)
sum by (container) (rate(netwatch_tx_bytes_total[1m]))
  / sum by (container) (rate(netwatch_tx_bytes_total[5m])) > 2
```

### Packet Analysis

```promql
# Packets per second per container
sum by (container) (rate(netwatch_tx_packets_total[1m]))

# Average packet size (bytes/packet) - small values mean chatty protocols
sum by (container) (rate(netwatch_tx_bytes_total[1m]))
  / sum by (container) (rate(netwatch_tx_packets_total[1m]))
```

## Docker Compose

The lab stack includes Prometheus out of the box:

```bash
docker compose -f docker-compose.lab.yml up --build
```

Then open `http://localhost:9090` to query.
