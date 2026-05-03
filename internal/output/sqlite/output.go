package sqliteoutput

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"docker-net-ebpf/netwatch"
	_ "modernc.org/sqlite"
)

type Output struct {
	mu   sync.Mutex
	db   *sql.DB
	stmt *sql.Stmt
}

func New(path string) (*Output, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create sqlite output directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite output: %w", err)
	}

	if err := initialize(db); err != nil {
		db.Close()
		return nil, err
	}

	stmt, err := db.Prepare(`
		INSERT INTO traffic_samples (
			timestamp,
			interval_ns,
			container_id,
			container_name,
			cgroup_id,
			runtime,
			direction,
			remote_ip,
			protocol,
			rx_bytes_delta,
			tx_bytes_delta,
			rx_packets_delta,
			tx_packets_delta,
			rx_bytes_total,
			tx_bytes_total,
			rx_packets_total,
			tx_packets_total
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("prepare sqlite insert: %w", err)
	}

	return &Output{db: db, stmt: stmt}, nil
}

func initialize(db *sql.DB) error {
	statements := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`CREATE TABLE IF NOT EXISTS traffic_samples (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			interval_ns INTEGER NOT NULL,
			container_id TEXT NOT NULL,
			container_name TEXT NOT NULL,
			cgroup_id INTEGER NOT NULL,
			runtime TEXT NOT NULL,
			direction TEXT NOT NULL,
			remote_ip TEXT,
			protocol TEXT,
			rx_bytes_delta INTEGER NOT NULL,
			tx_bytes_delta INTEGER NOT NULL,
			rx_packets_delta INTEGER NOT NULL,
			tx_packets_delta INTEGER NOT NULL,
			rx_bytes_total INTEGER NOT NULL,
			tx_bytes_total INTEGER NOT NULL,
			rx_packets_total INTEGER NOT NULL,
			tx_packets_total INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_samples_timestamp ON traffic_samples(timestamp);`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_samples_container_time ON traffic_samples(container_name, timestamp);`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_samples_remote_ip_time ON traffic_samples(remote_ip, timestamp);`,
	}

	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("initialize sqlite output: %w", err)
		}
	}

	return nil
}

func (o *Output) Write(_ context.Context, samples []netwatch.TrafficSample) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	tx, err := o.db.Begin()
	if err != nil {
		return fmt.Errorf("begin sqlite transaction: %w", err)
	}
	defer tx.Rollback()

	stmt := tx.Stmt(o.stmt)
	defer stmt.Close()

	for _, sample := range samples {
		var remoteIP any
		if sample.Remote.Addr.IsValid() {
			remoteIP = sample.Remote.Addr.String()
		}

		protocol := sample.Remote.Protocol.String()
		if sample.Remote.Protocol == netwatch.ProtocolUnknown {
			protocol = ""
		}

		if _, err := stmt.Exec(
			sample.Timestamp.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			sample.Interval.Nanoseconds(),
			sample.Container.ID,
			sample.Container.Name,
			sample.Container.CgroupID,
			sample.Container.Runtime,
			directionForSample(sample),
			remoteIP,
			protocol,
			sample.RxBytesDelta,
			sample.TxBytesDelta,
			sample.RxPacketsDelta,
			sample.TxPacketsDelta,
			sample.RxBytesTotal,
			sample.TxBytesTotal,
			sample.RxPacketsTotal,
			sample.TxPacketsTotal,
		); err != nil {
			return fmt.Errorf("insert sqlite sample: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite transaction: %w", err)
	}

	return nil
}

func (o *Output) Close() error {
	var err error
	if o.stmt != nil {
		err = o.stmt.Close()
	}
	if o.db != nil {
		if closeErr := o.db.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}
	return err
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
