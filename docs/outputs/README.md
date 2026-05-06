# Outputs

`docker-net-ebpf` can send the same traffic samples to multiple outputs at once.

Examples:

```bash
sudo docker-net-ebpf watch console prometheus
sudo docker-net-ebpf record jsonl sqlite
sudo docker-net-ebpf record jsonl ./traffic.jsonl sqlite ./traffic.db prometheus :9099
```

## How output selection works

Outputs are positional.

```bash
docker-net-ebpf <command> <output> [path-or-address] <output> [path-or-address] ...
```

Rules:

- If the token after an output is **not** another output name, it is treated as that output's path or listen address.
- If the token after an output **is** another output name, the current output gets its default destination.
- `watch` defaults to `console` when no outputs are provided.
- `record` defaults to `jsonl` when no outputs are provided.

Supported output names and aliases:

| Output | Aliases | Default destination |
|--------|---------|---------------------|
| `console` | `stdout` | none |
| `jsonl` | `json` | `output/traffic.jsonl` |
| `sqlite` | `sqlite3`, `db` | `output/traffic.db` |
| `prometheus` | `prom` | `:9099` |

## Multiple outputs

When you specify more than one output, `docker-net-ebpf` writes the same batch of `TrafficSample` values to each destination.

That fanout behavior is internal — you do not configure a separate `fanout` output. You just list the outputs you want.

```bash
sudo docker-net-ebpf record console jsonl sqlite prometheus
```

## Output guides

- [Console](console.md)
- [JSONL](jsonl.md)
- [SQLite](sqlite.md)
- [Prometheus](prometheus.md)
