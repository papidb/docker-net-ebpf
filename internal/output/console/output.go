package consoleoutput

import (
	"context"
	"fmt"
	"strings"

	"docker-net-ebpf/netwatch"
)

type Output struct{}

func New() *Output {
	return &Output{}
}

func (o *Output) Write(_ context.Context, samples []netwatch.TrafficSample) error {
	hasDestinations := false
	for _, sample := range samples {
		if sample.Remote.Addr.IsValid() {
			hasDestinations = true
			break
		}
	}

	fmt.Print("\033[H\033[2J")
	if hasDestinations {
		fmt.Println("Docker network destinations from eBPF cgroup_skb")
		fmt.Println(strings.Repeat("-", 136))
		fmt.Printf("%-24s %-14s %-8s %-22s %-8s %-15s %-15s %-15s\n", "CONTAINER", "ID", "DIR", "REMOTE IP", "PROTO", "RX", "TX", "TOTAL")
		fmt.Println(strings.Repeat("-", 136))
	} else {
		fmt.Println("Docker network usage from eBPF cgroup_skb")
		fmt.Println(strings.Repeat("-", 100))
		fmt.Printf("%-30s %-15s %-15s %-15s %-15s\n", "CONTAINER", "ID", "RX", "TX", "TOTAL")
		fmt.Println(strings.Repeat("-", 100))
	}

	for _, sample := range samples {
		total := sample.RxBytesTotal + sample.TxBytesTotal
		if hasDestinations {
			fmt.Printf(
				"%-24s %-14s %-8s %-22s %-8s %-15s %-15s %-15s\n",
				sample.Container.Name,
				shortID(sample.Container.ID),
				directionLabel(sample),
				endpointLabel(sample.Remote),
				sample.Remote.Protocol.String(),
				humanBytes(sample.RxBytesTotal),
				humanBytes(sample.TxBytesTotal),
				humanBytes(total),
			)
			continue
		}

		fmt.Printf(
			"%-30s %-15s %-15s %-15s %-15s\n",
			sample.Container.Name,
			shortID(sample.Container.ID),
			humanBytes(sample.RxBytesTotal),
			humanBytes(sample.TxBytesTotal),
			humanBytes(total),
		)
	}

	return nil
}

func (o *Output) Close() error {
	return nil
}

func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}

	return id[:12]
}

func endpointLabel(endpoint netwatch.Endpoint) string {
	if !endpoint.Addr.IsValid() {
		return "-"
	}

	return endpoint.Addr.String()
}

func directionLabel(sample netwatch.TrafficSample) string {
	switch {
	case sample.TxBytesTotal > 0 && sample.RxBytesTotal == 0:
		return netwatch.Egress.String()
	case sample.RxBytesTotal > 0 && sample.TxBytesTotal == 0:
		return netwatch.Ingress.String()
	case sample.RxBytesTotal == 0 && sample.TxBytesTotal == 0:
		return "unknown"
	default:
		return "mixed"
	}
}

func humanBytes(bytes uint64) string {
	const unit = 1024

	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}

	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f%ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
