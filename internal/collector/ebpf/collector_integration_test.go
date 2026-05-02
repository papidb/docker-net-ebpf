//go:build linux && integration

package ebpfcollector

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"docker-net-ebpf/netwatch"

	"golang.org/x/sys/unix"
)

const (
	ipv4HeaderSize = 20
	udpHeaderSize  = 8
)

func TestUDPEgressByteCount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	// The echo server must stay outside the observed cgroup or both sides of the
	// exchange get attributed to the same test container and the counts double.
	serverAddr := startUDPEchoServerProcess(t)

	cgroupPath := setupTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroupPath)

	collector, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer collector.Close()

	ctx := context.Background()
	container := netwatch.ContainerInfo{
		ID:         "test-udp-egress",
		Name:       "test-udp-egress",
		CgroupID:   cgroupID,
		CgroupPath: cgroupPath,
	}

	if err := collector.Attach(ctx, container); err != nil {
		t.Fatalf("Attach(): %v", err)
	}
	defer collector.Detach(ctx, container)

	payloadSize := 100
	packetCount := 20
	moveCurrentProcessToCgroup(t, cgroupPath)
	sendUDPPackets(t, serverAddr, payloadSize, packetCount)

	time.Sleep(100 * time.Millisecond)

	samples, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect(): %v", err)
	}

	expectedIPBytes := uint64(packetCount) * uint64(ipv4HeaderSize+udpHeaderSize+payloadSize)
	expectedPackets := uint64(packetCount)

	var egressBytes, egressPackets uint64
	for _, s := range samples {
		if s.CgroupID != cgroupID {
			continue
		}
		if s.Remote.Protocol != netwatch.ProtocolUDP {
			continue
		}
		if s.Direction != netwatch.Egress {
			continue
		}
		egressBytes += s.Bytes
		egressPackets += s.Packets
	}

	if egressPackets != expectedPackets {
		t.Errorf("egress packets = %d, want %d", egressPackets, expectedPackets)
	}
	if egressBytes != expectedIPBytes {
		t.Errorf("egress bytes = %d, want %d (payload=%d, ip+udp overhead=%d per packet)",
			egressBytes, expectedIPBytes, payloadSize, ipv4HeaderSize+udpHeaderSize)
	}
}

func TestUDPIngressByteCount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	// Keep the server outside the observed cgroup so ingress reflects only the
	// reply path into the client we moved into the test cgroup.
	serverAddr := startUDPEchoServerProcess(t)

	cgroupPath := setupTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroupPath)

	collector, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer collector.Close()

	ctx := context.Background()
	container := netwatch.ContainerInfo{
		ID:         "test-udp-ingress",
		Name:       "test-udp-ingress",
		CgroupID:   cgroupID,
		CgroupPath: cgroupPath,
	}

	if err := collector.Attach(ctx, container); err != nil {
		t.Fatalf("Attach(): %v", err)
	}
	defer collector.Detach(ctx, container)

	payloadSize := 200
	packetCount := 15
	moveCurrentProcessToCgroup(t, cgroupPath)
	sendUDPPackets(t, serverAddr, payloadSize, packetCount)

	time.Sleep(100 * time.Millisecond)

	samples, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect(): %v", err)
	}

	expectedIPBytes := uint64(packetCount) * uint64(ipv4HeaderSize+udpHeaderSize+payloadSize)
	expectedPackets := uint64(packetCount)

	var ingressBytes, ingressPackets uint64
	for _, s := range samples {
		if s.CgroupID != cgroupID {
			continue
		}
		if s.Remote.Protocol != netwatch.ProtocolUDP {
			continue
		}
		if s.Direction != netwatch.Ingress {
			continue
		}
		ingressBytes += s.Bytes
		ingressPackets += s.Packets
	}

	if ingressPackets != expectedPackets {
		t.Errorf("ingress packets = %d, want %d", ingressPackets, expectedPackets)
	}
	if ingressBytes != expectedIPBytes {
		t.Errorf("ingress bytes = %d, want %d (payload=%d, ip+udp overhead=%d per packet)",
			ingressBytes, expectedIPBytes, payloadSize, ipv4HeaderSize+udpHeaderSize)
	}
}

func TestUDPLargePayloadByteCount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	// Large payloads are where silent off-by-one header bugs show up, so this
	// uses the same isolated server pattern as the smaller UDP tests.
	serverAddr := startUDPEchoServerProcess(t)

	cgroupPath := setupTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroupPath)

	collector, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer collector.Close()

	ctx := context.Background()
	container := netwatch.ContainerInfo{
		ID:         "test-udp-large",
		Name:       "test-udp-large",
		CgroupID:   cgroupID,
		CgroupPath: cgroupPath,
	}

	if err := collector.Attach(ctx, container); err != nil {
		t.Fatalf("Attach(): %v", err)
	}
	defer collector.Detach(ctx, container)

	payloadSize := 4096
	packetCount := 20
	moveCurrentProcessToCgroup(t, cgroupPath)
	sendUDPPackets(t, serverAddr, payloadSize, packetCount)

	time.Sleep(100 * time.Millisecond)

	samples, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect(): %v", err)
	}

	expectedIPBytes := uint64(packetCount) * uint64(ipv4HeaderSize+udpHeaderSize+payloadSize)
	expectedPackets := uint64(packetCount)

	var egressBytes, egressPackets uint64
	for _, s := range samples {
		if s.CgroupID != cgroupID || s.Remote.Protocol != netwatch.ProtocolUDP || s.Direction != netwatch.Egress {
			continue
		}
		egressBytes += s.Bytes
		egressPackets += s.Packets
	}

	if egressPackets != expectedPackets {
		t.Errorf("egress packets = %d, want %d", egressPackets, expectedPackets)
	}
	if egressBytes != expectedIPBytes {
		t.Errorf("egress bytes = %d, want %d (payload=%d, ip+udp overhead=%d per packet)",
			egressBytes, expectedIPBytes, payloadSize, ipv4HeaderSize+udpHeaderSize)
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

// TestTCPByteCountMatchesTcpdump verifies that the eBPF collector reports the
// same total byte and packet counts for TCP traffic as an independent observer
// (tcpdump) sees at the network layer.
//
// WHY A SEPARATE ORACLE IS NEEDED FOR TCP
// ----------------------------------------
// For UDP the expected byte count is trivial to calculate:
//
//   packets * (IPv4 header + UDP header + payload)
//
// TCP is different. Every connection carries a variable number of SYN, ACK,
// FIN, and retransmit segments whose sizes cannot be predicted ahead of time.
// Re-implementing the kernel's TCP math in a test would couple the test to
// implementation details and still miss edge cases (e.g. Nagle, delayed ACK,
// TSO). Instead, we treat tcpdump as a ground-truth oracle: it reads the same
// raw IPv4 packets off the loopback interface that the eBPF program sees at
// the sk_buff level, sums their IPv4 total-length fields, and we compare.
//
// TEST TOPOLOGY
// -------------
//
//   ┌─────────────────────────────── loopback (lo) ───────────────────────────┐
//   │                                                                          │
//   │  TCP echo server subprocess          TCP client (this test process)      │
//   │  (parent cgroup – NOT observed)      (moved into observed test cgroup)   │
//   │  127.0.0.1:<serverPort>    <------>  127.0.0.1:<clientPort>              │
//   │                                                                          │
//   │              tcpdump --immediate-mode -i lo                              │
//   │              filter: "tcp and port <serverPort>"                         │
//   └──────────────────────────────────────────────────────────────────────────┘
//
// The echo server runs as a subprocess so it lives in a different cgroup from
// the client. That keeps both sides of the connection from being attributed to
// the same observed cgroup (which would double-count bytes).
func TestTCPByteCountMatchesTcpdump(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("tcpdump not installed")
	}

	// TCP carries handshake, ACK, and teardown traffic, so we capture packets and
	// sum IPv4 total lengths directly instead of re-implementing TCP math here.
	serverAddr := startTCPEchoServerProcess(t)
	serverPort := mustAddrPort(t, serverAddr).Port()
	stopCapture := startPCAPCapture(t, serverPort)

	cgroupPath := setupTestCgroup(t)
	cgroupID := mustCgroupID(t, cgroupPath)

	collector, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer collector.Close()

	ctx := context.Background()
	container := netwatch.ContainerInfo{
		ID:         "test-tcp-byte-count",
		Name:       "test-tcp-byte-count",
		CgroupID:   cgroupID,
		CgroupPath: cgroupPath,
	}

	if err := collector.Attach(ctx, container); err != nil {
		t.Fatalf("Attach(): %v", err)
	}
	defer collector.Detach(ctx, container)

	payload := []byte(strings.Repeat("x", 4096))
	moveCurrentProcessToCgroup(t, cgroupPath)
	clientPort := runTCPExchange(t, serverAddr, payload)

	time.Sleep(150 * time.Millisecond)
	packets := stopCapture()

	samples, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect(): %v", err)
	}

	expectedIngress, expectedEgress := sumCapturedTraffic(t, packets, serverPort, clientPort)
	actualIngress, actualEgress := sumCollectorTraffic(samples, cgroupID, netwatch.ProtocolTCP)

	if actualEgress.Packets != expectedEgress.Packets {
		t.Errorf("tcp egress packets = %d, want %d", actualEgress.Packets, expectedEgress.Packets)
	}
	if actualEgress.Bytes != expectedEgress.Bytes {
		t.Errorf("tcp egress bytes = %d, want %d", actualEgress.Bytes, expectedEgress.Bytes)
	}
	if actualIngress.Packets != expectedIngress.Packets {
		t.Errorf("tcp ingress packets = %d, want %d", actualIngress.Packets, expectedIngress.Packets)
	}
	if actualIngress.Bytes != expectedIngress.Bytes {
		t.Errorf("tcp ingress bytes = %d, want %d", actualIngress.Bytes, expectedIngress.Bytes)
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

	return path
}

func moveCurrentProcessToCgroup(t *testing.T, path string) {
	t.Helper()

	originalPath := currentCgroupPath(t)
	t.Cleanup(func() {
		pid := os.Getpid()
		if err := os.WriteFile(filepath.Join(originalPath, "cgroup.procs"), []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
			t.Fatalf("restore process to original cgroup: %v", err)
		}
	})

	pid := os.Getpid()
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		t.Fatalf("move process to test cgroup: %v", err)
	}
}

func currentCgroupPath(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatalf("read /proc/self/cgroup: %v", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" {
			return filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(parts[2], "/"))
		}
	}

	t.Fatal("unified cgroup v2 path not found")
	return ""
}

type trafficTotals struct {
	Bytes   uint64
	Packets uint64
}

var (
	pcapMagicMicrosecondsLittleEndian = []byte{0xd4, 0xc3, 0xb2, 0xa1}
)

type capturedPacket struct {
	IPTotalLen uint16
	Protocol   uint8
	SrcPort    uint16
	DstPort    uint16
}

func sumCollectorTraffic(samples []netwatch.RawTrafficSample, cgroupID uint64, protocol netwatch.Protocol) (ingress, egress trafficTotals) {
	for _, s := range samples {
		if s.CgroupID != cgroupID || s.Remote.Protocol != protocol {
			continue
		}
		if s.Direction == netwatch.Egress {
			egress.Bytes += s.Bytes
			egress.Packets += s.Packets
			continue
		}
		ingress.Bytes += s.Bytes
		ingress.Packets += s.Packets
	}
	return
}

func sumCapturedTraffic(t *testing.T, packets []capturedPacket, serverPort, clientPort uint16) (ingress, egress trafficTotals) {
	t.Helper()

	for _, packet := range packets {
		if packet.Protocol != uint8(netwatch.ProtocolTCP) {
			continue
		}

		switch {
		case packet.SrcPort == clientPort && packet.DstPort == serverPort:
			egress.Bytes += uint64(packet.IPTotalLen)
			egress.Packets++
		case packet.SrcPort == serverPort && packet.DstPort == clientPort:
			ingress.Bytes += uint64(packet.IPTotalLen)
			ingress.Packets++
		}
	}

	if ingress.Packets == 0 && egress.Packets == 0 {
		t.Logf("no matching packets: serverPort=%d clientPort=%d total=%d", serverPort, clientPort, len(packets))
		for i, p := range packets {
			t.Logf("  [%d] proto=%d src=%d dst=%d iplen=%d", i, p.Protocol, p.SrcPort, p.DstPort, p.IPTotalLen)
		}
		t.Fatal("pcap capture contained no matching TCP packets")
	}

	return
}

func mustAddrPort(t *testing.T, addr string) netip.AddrPort {
	t.Helper()

	addrPort, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatalf("parse addr %q: %v", addr, err)
	}
	return addrPort
}

func mustCgroupID(t *testing.T, path string) uint64 {
	t.Helper()

	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}

	return st.Ino
}

func startUDPEchoServerProcess(t *testing.T) string {
	t.Helper()

	// The helper process stays in the parent's original cgroup while the test
	// process moves into the observed cgroup before generating traffic.
	cmd := exec.Command(os.Args[0], "-test.run=TestUDPServerHelperProcess")
	cmd.Env = append(os.Environ(), "GO_WANT_UDP_SERVER_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start udp helper: %v", err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	reader := bufio.NewReader(stdout)
	addr, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read helper address: %v", err)
	}

	return addr[:len(addr)-1]
}

func startTCPEchoServerProcess(t *testing.T) string {
	t.Helper()

	// TCP uses the same subprocess pattern so only the client side is attributed
	// to the observed cgroup during the integration test.
	cmd := exec.Command(os.Args[0], "-test.run=TestTCPServerHelperProcess")
	cmd.Env = append(os.Environ(), "GO_WANT_TCP_SERVER_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start tcp helper: %v", err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	reader := bufio.NewReader(stdout)
	addr, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read helper address: %v", err)
	}

	return strings.TrimSpace(addr)
}

// ┌─────────────────────────────────────────────────────────────────────────────┐
// │  PCAP CAPTURE DESIGN NOTES – read this before touching the capture helpers  │
// └─────────────────────────────────────────────────────────────────────────────┘
//
// Getting a reliable pcap capture in a Go integration test turned out to be
// surprisingly subtle. Three separate bugs had to be diagnosed and fixed. They
// are documented here so the next person does not have to rediscover them.
//
// ── BUG 1: tcpdump -w <file> wrote zero bytes ────────────────────────────────
//
// The original implementation used:
//
//   tcpdump -i lo -U -w /tmp/.../tcp-PORT.pcap tcp and port PORT
//
// tcpdump printed "0 packets captured / 20 packets received by filter".  The
// kernel BPF filter matched every packet, but the pcap file only ever contained
// the 24-byte global header – no packet records.
//
// Root cause: TPACKET_V3 ring-buffer block batching (see Bug 2 below).  The
// file-write path was a red herring – the same symptom appeared when switching
// to stdout (-w -).  We kept the stdout approach anyway because it removes one
// failure mode (filesystem permissions / tmpfs write restrictions under some
// Linux container / VM configurations).
//
// ── BUG 2: TPACKET_V3 block-retirement timeout (the real culprit) ─────────────
//
// Modern libpcap on Linux uses AF_PACKET with TPACKET_V3, a ring-buffer API
// that batches packets into fixed-size "blocks" before handing them to
// userspace.  A block is only made available to userspace when EITHER:
//
//   a) the block is full (all frame slots used), OR
//   b) a per-block retirement timeout fires (~200 ms by default).
//
// The test sent SIGINT after a 150 ms sleep – shorter than the 200 ms timeout.
// The kernel had already matched and buffered 20 packets in the ring, but the
// block had not yet retired, so pcap_dispatch() returned 0 packets dispatched.
// That is why "packets received by filter" (a kernel-level counter) was 20
// while "packets captured" (a userspace dispatch counter) was 0.
//
// Fix: pass --immediate-mode to tcpdump.  This tells libpcap to call
// pcap_set_immediate_mode(), which forces the kernel to use TPACKET_V2 (or
// disables block coalescing in V3) and deliver each packet to userspace as
// soon as it arrives, with no batching delay.
//
// Alternative: increase the sleep between sending traffic and calling
// stopCapture() to > 200 ms.  That works but is fragile because the timeout
// is not guaranteed and varies across kernel versions and configurations.
// --immediate-mode is the correct, portable fix.
//
// ── BUG 3: link-type handling in the hand-rolled pcap parser ─────────────────
//
// The original parseCapturedPacket assumed the capture used DLT_EN10MB
// (Ethernet, 14-byte header, ethertype at bytes 12–13).  On the loopback
// interface tcpdump also reports DLT_EN10MB (link type 1) – confirmed by
// reading the network field at bytes 20–23 of the pcap global header.
//
// However, if tcpdump is run with `-i any` instead of `-i lo`, libpcap uses
// DLT_LINUX_SLL (Linux cooked socket, link type 113) with a 16-byte header
// and ethertype at bytes 14–15.  The parser was updated to handle both link
// types so it will keep working if the interface is ever changed.
//
//   DLT_EN10MB  (1)  :  [dst 6B][src 6B][ethertype 2B] | IP header ...
//   DLT_LINUX_SLL (113): [pkt-type 2B][hw-type 2B][hw-len 2B][hw-addr 8B]
//                        [protocol 2B]               | IP header ...
//
// ── STDOUT PIPE vs FILE ──────────────────────────────────────────────────────
//
// We use "-w -" (write pcap to stdout) and collect the bytes via io.ReadAll on
// the StdoutPipe rather than writing to a file with "-w <path>".  Reasons:
//
//   1. Avoids silent write failures if the temp directory is on a filesystem
//      that rejects writes from the tcpdump process (AppArmor, read-only tmpfs,
//      etc.).  A pipe write failure would surface immediately as a broken pipe.
//
//   2. io.ReadAll reads until EOF, which only occurs after cmd.Wait() (process
//      exit), so we are guaranteed to have all bytes before we parse.  With a
//      file we had to trust that os.File.Close() flushed everything, which is
//      not always the case with SIGINT-initiated shutdown.
//
// ── STDERR DRAIN GOROUTINE ───────────────────────────────────────────────────
//
// tcpdump writes its "listening on …" startup message and final statistics to
// stderr.  We read stderr in a goroutine for two reasons:
//
//   1. The "listening on" line tells us tcpdump has opened the capture socket
//      and is ready; we must not generate traffic before that point.
//
//   2. If we stop reading stderr, the pipe buffer fills, tcpdump blocks in a
//      write() call, and cmd.Wait() deadlocks.  The goroutine keeps draining
//      after "listening on" so that never happens.
//
// startPCAPCapture returns a stop function.  Call it after all traffic has been
// sent; it signals tcpdump with SIGINT and returns the parsed packet slice.
func startPCAPCapture(t *testing.T, serverPort uint16) func() []capturedPacket {
	t.Helper()

	// --immediate-mode: bypass TPACKET_V3 block batching (see design notes above).
	// -w -: write pcap to stdout instead of a file (see design notes above).
	// -U: flush each packet to the output immediately (belt-and-suspenders with
	//     --immediate-mode; ensures no stdio buffering on the write side either).
	cmd := exec.Command("tcpdump", "--immediate-mode", "-i", "lo", "-U", "-w", "-", "tcp", "and", "port", strconv.Itoa(int(serverPort)))

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("tcpdump stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("tcpdump stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start tcpdump: %v", err)
	}

	// Collect all pcap bytes from stdout in the background.
	pcapData := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(stdout)
		pcapData <- data
	}()

	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("tcpdump: %s", line)
			if strings.Contains(line, "listening on") {
				close(ready)
				for scanner.Scan() {
					t.Logf("tcpdump: %s", scanner.Text())
				}
				return
			}
		}
		close(ready)
	}()

	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("tcpdump did not become ready")
	}

	return func() []capturedPacket {
		_ = cmd.Process.Signal(os.Interrupt)
		if err := cmd.Wait(); err != nil {
			t.Logf("tcpdump exit: %v", err)
		}
		data := <-pcapData
		packets, linkType, err := readPCAPPacketsFromBytes(t, data)
		if err != nil {
			t.Fatalf("read pcap: %v", err)
		}
		t.Logf("pcap: linkType=%d parsed=%d packets", linkType, len(packets))
		return packets
	}
}

// Link-type constants from the pcap global header (bytes 20–23).
// See the PCAP CAPTURE DESIGN NOTES above for why both are handled.
const (
	dltEN10MB   = 1   // Ethernet – used by tcpdump -i lo on Linux
	dltLinuxSLL = 113 // Linux cooked socket – used by tcpdump -i any
)

// readPCAPPacketsFromBytes parses a pcap byte stream (e.g. from a stdout pipe)
// and returns all packets that could be decoded as IPv4 TCP frames.
//
// The pcap format used here is the legacy "microsecond-resolution, little-endian"
// variant (magic 0xd4c3b2a1).  Modern tcpdump can also produce pcapng
// (magic 0x0a0d0d0a); if that ever becomes the default on the target system
// this function will return an "unsupported pcap magic" error rather than
// silently returning zero packets.
func readPCAPPacketsFromBytes(t *testing.T, data []byte) ([]capturedPacket, int, error) {
	t.Helper()

	if len(data) < 24 {
		return nil, 0, fmt.Errorf("pcap too small (%d bytes)", len(data))
	}
	if string(data[:4]) != string(pcapMagicMicrosecondsLittleEndian) {
		return nil, 0, fmt.Errorf("unsupported pcap magic %x", data[:4])
	}

	linkType := int(binary.LittleEndian.Uint32(data[20:24]))

	offset := 24
	var packets []capturedPacket
	for offset+16 <= len(data) {
		capturedLen := int(binary.LittleEndian.Uint32(data[offset+8 : offset+12]))
		offset += 16
		if offset+capturedLen > len(data) {
			return nil, linkType, fmt.Errorf("truncated packet data")
		}

		packet, ok := parseCapturedPacket(data[offset:offset+capturedLen], linkType)
		if ok {
			packets = append(packets, packet)
		}
		offset += capturedLen
	}

	return packets, linkType, nil
}

// parseCapturedPacket decodes one raw pcap frame into a capturedPacket.
//
// The frame layout depends on the link type reported in the pcap global header
// (see the PCAP CAPTURE DESIGN NOTES and dltEN10MB / dltLinuxSLL constants).
// Only IPv4 TCP frames are accepted; everything else returns (_, false) so the
// caller can skip it silently.
//
// Port numbers are read from the first four bytes of the transport header,
// which is correct for both TCP and UDP.  We only call this path for TCP but
// keeping it generic costs nothing and avoids a future footgun.
func parseCapturedPacket(frame []byte, linkType int) (capturedPacket, bool) {
	var headerLen int
	var ethertypeOffset int
	switch linkType {
	case dltEN10MB:
		// Standard Ethernet: 6-byte dst MAC, 6-byte src MAC, 2-byte ethertype.
		headerLen = 14
		ethertypeOffset = 12
	case dltLinuxSLL:
		// Linux cooked socket (tcpdump -i any): 16-byte header, ethertype at 14.
		headerLen = 16
		ethertypeOffset = 14
	default:
		return capturedPacket{}, false
	}

	if len(frame) < headerLen+20 {
		return capturedPacket{}, false
	}
	if binary.BigEndian.Uint16(frame[ethertypeOffset:ethertypeOffset+2]) != 0x0800 {
		return capturedPacket{}, false
	}

	ip := frame[headerLen:]
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl+4 || ihl < 20 {
		return capturedPacket{}, false
	}
	if ip[9] != uint8(netwatch.ProtocolTCP) {
		return capturedPacket{}, false
	}

	return capturedPacket{
		IPTotalLen: binary.BigEndian.Uint16(ip[2:4]),
		Protocol:   ip[9],
		SrcPort:    binary.BigEndian.Uint16(ip[ihl : ihl+2]),
		DstPort:    binary.BigEndian.Uint16(ip[ihl+2 : ihl+4]),
	}, true
}

func TestUDPServerHelperProcess(*testing.T) {
	if os.Getenv("GO_WANT_UDP_SERVER_HELPER") != "1" {
		return
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(conn.LocalAddr().String())

	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			os.Exit(0)
		}
		if _, err := conn.WriteTo(buf[:n], addr); err != nil {
			os.Exit(1)
		}
	}
}

func TestTCPServerHelperProcess(*testing.T) {
	if os.Getenv("GO_WANT_TCP_SERVER_HELPER") != "1" {
		return
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(ln.Addr().String())

	for {
		conn, err := ln.Accept()
		if err != nil {
			os.Exit(0)
		}

		go func() {
			defer conn.Close()
			buf := make([]byte, 65535)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				if _, err := conn.Write(buf[:n]); err != nil {
					return
				}
			}
		}()
	}
}

func sendUDPPackets(t *testing.T, serverAddr string, payloadSize, count int) {
	t.Helper()

	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	recvBuf := make([]byte, payloadSize)

	for range count {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write udp: %v", err)
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(recvBuf)
		if err != nil {
			t.Fatalf("read udp echo: %v", err)
		}
		if n != payloadSize {
			t.Fatalf("echo returned %d bytes, want %d", n, payloadSize)
		}
	}
}

func runTCPExchange(t *testing.T, serverAddr string, payload []byte) uint16 {
	t.Helper()

	server := mustAddrPort(t, serverAddr)
	conn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(server))
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer conn.Close()

	if err := conn.SetNoDelay(true); err != nil {
		t.Fatalf("set nodelay: %v", err)
	}

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write tcp: %v", err)
	}

	recvBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, recvBuf); err != nil {
		t.Fatalf("read tcp echo: %v", err)
	}

	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	return conn.LocalAddr().(*net.TCPAddr).AddrPort().Port()
}
