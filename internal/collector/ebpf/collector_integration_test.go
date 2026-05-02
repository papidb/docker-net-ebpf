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

func startPCAPCapture(t *testing.T, serverPort uint16) func() []capturedPacket {
	t.Helper()

	// Write pcap data to stdout (-w -) to avoid any file-path permission issues
	// on the tmpfs used by t.TempDir() under some Linux configurations.
	// --immediate-mode disables TPACKET_V3 block-batching so packets are
	// dispatched to userspace as they arrive rather than waiting for the
	// block-retirement timeout (~200 ms), which would cause us to miss them
	// when SIGINT fires after a shorter sleep.
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

const (
	dltEN10MB   = 1   // Ethernet
	dltLinuxSLL = 113 // Linux cooked socket (used by tcpdump on lo)
)

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

func parseCapturedPacket(frame []byte, linkType int) (capturedPacket, bool) {
	var headerLen int
	var ethertypeOffset int
	switch linkType {
	case dltEN10MB:
		headerLen = 14
		ethertypeOffset = 12
	case dltLinuxSLL:
		// Linux cooked socket: 16-byte header, ethertype at bytes 14-15
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
