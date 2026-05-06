# Console Output

Console output is the default for `watch`.

```bash
sudo docker-net-ebpf watch
sudo docker-net-ebpf watch console
sudo docker-net-ebpf watch console prometheus
```

## What it does

- clears the terminal on every write
- prints a live table of the latest aggregated traffic samples
- shows one row per container + remote IP + protocol

If destination data is present, the table includes:

- container name
- short container ID
- inferred direction (`ingress`, `egress`, or `mixed`)
- remote IP
- protocol
- RX / TX / TOTAL bytes

If destination data is missing, it falls back to a simpler container totals table.

## Best use

Use console output when you want a live operator view:

```bash
sudo docker-net-ebpf watch console
```

If you also want durable storage or scraping, combine it with another output:

```bash
sudo docker-net-ebpf watch console jsonl
sudo docker-net-ebpf watch console prometheus :9099
```

## Notes

- Console output is for humans, not for machine ingestion.
- It does not store history.
- It rewrites the screen each interval, so it works best in an interactive terminal.
