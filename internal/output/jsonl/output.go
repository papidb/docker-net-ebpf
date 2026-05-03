package jsonloutput

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"docker-net-ebpf/netwatch"
)

type Output struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
}

func New(path string) (*Output, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create jsonl output directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open jsonl output: %w", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)

	return &Output{file: file, encoder: encoder}, nil
}

type record struct {
	Timestamp      string `json:"timestamp"`
	Interval       string `json:"interval"`
	ContainerID    string `json:"container_id"`
	ContainerName  string `json:"container_name"`
	CgroupID       uint64 `json:"cgroup_id"`
	Runtime        string `json:"runtime"`
	Direction      string `json:"direction"`
	RemoteIP       string `json:"remote_ip,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	RxBytesDelta   uint64 `json:"rx_bytes_delta"`
	TxBytesDelta   uint64 `json:"tx_bytes_delta"`
	RxPacketsDelta uint64 `json:"rx_packets_delta"`
	TxPacketsDelta uint64 `json:"tx_packets_delta"`
	RxBytesTotal   uint64 `json:"rx_bytes_total"`
	TxBytesTotal   uint64 `json:"tx_bytes_total"`
	RxPacketsTotal uint64 `json:"rx_packets_total"`
	TxPacketsTotal uint64 `json:"tx_packets_total"`
}

func (o *Output) Write(_ context.Context, samples []netwatch.TrafficSample) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	for _, sample := range samples {
		item := record{
			Timestamp:      sample.Timestamp.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			Interval:       sample.Interval.String(),
			ContainerID:    sample.Container.ID,
			ContainerName:  sample.Container.Name,
			CgroupID:       sample.Container.CgroupID,
			Runtime:        sample.Container.Runtime,
			Direction:      directionForSample(sample),
			RxBytesDelta:   sample.RxBytesDelta,
			TxBytesDelta:   sample.TxBytesDelta,
			RxPacketsDelta: sample.RxPacketsDelta,
			TxPacketsDelta: sample.TxPacketsDelta,
			RxBytesTotal:   sample.RxBytesTotal,
			TxBytesTotal:   sample.TxBytesTotal,
			RxPacketsTotal: sample.RxPacketsTotal,
			TxPacketsTotal: sample.TxPacketsTotal,
		}

		if sample.Remote.Addr.IsValid() {
			item.RemoteIP = sample.Remote.Addr.String()
		}
		if sample.Remote.Protocol != netwatch.ProtocolUnknown {
			item.Protocol = sample.Remote.Protocol.String()
		}

		if err := o.encoder.Encode(item); err != nil {
			return fmt.Errorf("write jsonl record: %w", err)
		}
	}

	return nil
}

func (o *Output) Close() error {
	if o.file == nil {
		return nil
	}
	return o.file.Close()
}

func directionForSample(sample netwatch.TrafficSample) string {
	switch {
	case sample.TxBytesTotal > 0 && sample.RxBytesTotal == 0:
		return netwatch.Egress.String()
	case sample.RxBytesTotal > 0 && sample.TxBytesTotal == 0:
		return netwatch.Ingress.String()
	default:
		return "mixed"
	}
}
