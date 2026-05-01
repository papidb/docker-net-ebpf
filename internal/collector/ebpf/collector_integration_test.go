//go:build linux && integration

package ebpfcollector

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"docker-net-ebpf/netwatch"
	"golang.org/x/sys/unix"
)

func TestCollectorIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	cgroupPath := setupTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroupPath)

	collector, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer collector.Close()

	ctx := context.Background()
	container := netwatch.ContainerInfo{
		ID:         "test-integration",
		Name:       "test-integration",
		CgroupID:   cgroupID,
		CgroupPath: cgroupPath,
	}

	if err := collector.Attach(ctx, container); err != nil {
		t.Fatalf("Attach(): %v", err)
	}
	defer collector.Detach(ctx, container)

	serverAddr := startTCPEchoServer(t)
	generateTCPTraffic(t, serverAddr)

	time.Sleep(100 * time.Millisecond)

	samples, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect(): %v", err)
	}

	if len(samples) == 0 {
		t.Fatal("expected at least one sample, got none")
	}

	var foundTCP bool
	for _, s := range samples {
		if s.Remote.Protocol == netwatch.ProtocolTCP && s.Remote.Addr.IsValid() {
			foundTCP = true
			if s.Bytes == 0 {
				t.Error("TCP sample has zero bytes")
			}
			if s.Packets == 0 {
				t.Error("TCP sample has zero packets")
			}
			t.Logf("sample: cgroup=%d dir=%s remote=%s proto=%s bytes=%d packets=%d",
				s.CgroupID, s.Direction, s.Remote.Addr, s.Remote.Protocol, s.Bytes, s.Packets)
		}
	}

	if !foundTCP {
		t.Error("no TCP samples with valid remote address found")
	}
}

func TestCollectorAttachDetach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	cgroupPath := setupTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroupPath)

	collector, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer collector.Close()

	ctx := context.Background()
	container := netwatch.ContainerInfo{
		ID:         "test-attach-detach",
		Name:       "test-attach-detach",
		CgroupID:   cgroupID,
		CgroupPath: cgroupPath,
	}

	if err := collector.Attach(ctx, container); err != nil {
		t.Fatalf("Attach(): %v", err)
	}

	if err := collector.Detach(ctx, container); err != nil {
		t.Fatalf("Detach(): %v", err)
	}

	if len(collector.links) != 0 {
		t.Errorf("links map not empty after detach: %d entries", len(collector.links))
	}
}

func setupTestCgroup(t *testing.T) string {
	t.Helper()

	base := "/sys/fs/cgroup"
	path := filepath.Join(base, "netwatch-test", fmt.Sprintf("test-%d", os.Getpid()))

	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("create test cgroup: %v", err)
	}

	t.Cleanup(func() {
		os.Remove(path)
		os.Remove(filepath.Dir(path))
	})

	pid := os.Getpid()
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		t.Fatalf("move process to test cgroup: %v", err)
	}

	return path
}

func mustCgroupID(t *testing.T, path string) uint64 {
	t.Helper()

	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}

	return st.Ino
}

func startTCPEchoServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close()
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					conn.Write(buf[:n])
				}
			}()
		}
	}()

	return ln.Addr().String()
}

func generateTCPTraffic(t *testing.T, addr string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello from integration test")
	for range 10 {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}

		buf := make([]byte, len(payload))
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
}
