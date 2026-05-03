package jsonloutput

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"docker-net-ebpf/netwatch"
	"net/netip"
)

func TestWriteJSONL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "traffic.jsonl")

	output, err := New(path)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer output.Close()

	samples := []netwatch.TrafficSample{sample()}
	if err := output.Write(context.Background(), samples); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	if err := output.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}

	if got := record["container_name"]; got != "lab-egress" {
		t.Fatalf("unexpected container_name: %v", got)
	}

	if got := record["remote_ip"]; got != "162.159.140.220" {
		t.Fatalf("unexpected remote_ip: %v", got)
	}

	if got := record["direction"]; got != "egress" {
		t.Fatalf("unexpected direction: %v", got)
	}
}

func sample() netwatch.TrafficSample {
	return netwatch.TrafficSample{
		Timestamp: time.Unix(1_700_000_000, 0).UTC(),
		Interval:  2 * time.Second,
		Container: netwatch.ContainerInfo{ID: "abc123", Name: "lab-egress", CgroupID: 7, Runtime: "docker"},
		Remote:    netwatch.Endpoint{Addr: netip.MustParseAddr("162.159.140.220"), Protocol: netwatch.ProtocolTCP},
		TxBytesDelta:   2048,
		TxPacketsDelta: 8,
		TxBytesTotal:   4096,
		TxPacketsTotal: 16,
	}
}
