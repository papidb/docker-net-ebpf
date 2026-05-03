package sqliteoutput

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"docker-net-ebpf/netwatch"
	"net/netip"
	_ "modernc.org/sqlite"
)

func TestWriteSQLite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "traffic.db")

	output, err := New(path)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer output.Close()

	if err := output.Write(context.Background(), []netwatch.TrafficSample{sample()}); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	if err := output.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	defer db.Close()

	var count int
	var containerName, remoteIP, direction string
	if err := db.QueryRow(`SELECT COUNT(*), MAX(container_name), MAX(remote_ip), MAX(direction) FROM traffic_samples`).Scan(&count, &containerName, &remoteIP, &direction); err != nil {
		t.Fatalf("QueryRow returned error: %v", err)
	}

	if count != 1 {
		t.Fatalf("expected 1 row, got %d", count)
	}

	if containerName != "lab-egress" || remoteIP != "162.159.140.220" || direction != "egress" {
		t.Fatalf("unexpected row values: name=%s ip=%s direction=%s", containerName, remoteIP, direction)
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
