# SQLite Output

SQLite output writes traffic samples into a local SQLite database.

```bash
sudo docker-net-ebpf record sqlite
sudo docker-net-ebpf record sqlite ./traffic.db
sudo docker-net-ebpf record jsonl sqlite ./data/traffic.db
```

Default path:

```text
output/traffic.db
```

Parent directories are created automatically.

## Best use

Use SQLite when you want:

- persistent local history
- structured queries over time ranges
- a future foundation for `top`-style analysis

## Table

Samples are written to:

```text
traffic_samples
```

Key stored fields include:

- `timestamp`
- `interval_ns`
- `container_id`
- `container_name`
- `cgroup_id`
- `runtime`
- `direction`
- `remote_ip`
- `protocol`
- delta counters
- total counters

Indexes are created for:

- `timestamp`
- `container_name, timestamp`
- `remote_ip, timestamp`

The database is initialized with:

- `PRAGMA journal_mode=WAL`
- `PRAGMA synchronous=NORMAL`

## Useful queries

```sql
-- newest samples first
SELECT timestamp, container_name, remote_ip, tx_bytes_total
FROM traffic_samples
ORDER BY timestamp DESC
LIMIT 20;

-- total transmitted bytes by container
SELECT container_name, SUM(tx_bytes_delta) AS tx_bytes
FROM traffic_samples
GROUP BY container_name
ORDER BY tx_bytes DESC;

-- traffic to a specific remote IP
SELECT timestamp, container_name, rx_bytes_delta, tx_bytes_delta
FROM traffic_samples
WHERE remote_ip = '162.159.140.220'
ORDER BY timestamp DESC;
```

## Notes

- SQLite is a better fit than JSONL when you care about querying rather than raw export.
- The current output writes samples; higher-level query commands can build on the same database later.
