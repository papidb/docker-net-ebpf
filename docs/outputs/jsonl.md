# JSONL Output

JSONL output appends one JSON object per sample to a file.

```bash
sudo docker-net-ebpf record jsonl
sudo docker-net-ebpf record jsonl ./traffic.jsonl
sudo docker-net-ebpf record console jsonl ./logs/traffic.jsonl
```

Default path:

```text
output/traffic.jsonl
```

Parent directories are created automatically.

## Best use

Use JSONL when you want:

- an append-only record of samples
- easy ingestion into scripts or external tools
- a format that is easy to inspect with standard Unix tooling

## Record shape

Each line contains fields like:

- `timestamp`
- `interval`
- `container_id`
- `container_name`
- `cgroup_id`
- `runtime`
- `direction`
- `remote_ip`
- `protocol`
- `rx_bytes_delta`, `tx_bytes_delta`
- `rx_packets_delta`, `tx_packets_delta`
- `rx_bytes_total`, `tx_bytes_total`
- `rx_packets_total`, `tx_packets_total`

Example:

```json
{"timestamp":"2023-11-14T22:13:20Z","interval":"2s","container_id":"abc123","container_name":"lab-egress","cgroup_id":7,"runtime":"docker","direction":"egress","remote_ip":"162.159.140.220","protocol":"tcp","rx_bytes_delta":0,"tx_bytes_delta":2048,"rx_packets_delta":0,"tx_packets_delta":8,"rx_bytes_total":0,"tx_bytes_total":4096,"rx_packets_total":0,"tx_packets_total":16}
```

## Notes

- JSONL is append-only.
- It is a good default for `record` because it is simple and portable.
- Use SQLite instead if you want indexed historical queries.
