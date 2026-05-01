package ebpfcollector

import (
	"net/netip"
	"testing"
	"time"

	"docker-net-ebpf/netwatch"
)

func TestAddrFromKernelIPv4(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected netip.Addr
	}{
		{
			name:     "loopback 127.0.0.1 in little-endian kernel order",
			input:    0x0100007f,
			expected: netip.MustParseAddr("127.0.0.1"),
		},
		{
			name:     "10.0.0.1",
			input:    0x0100000a,
			expected: netip.MustParseAddr("10.0.0.1"),
		},
		{
			name:     "192.168.1.100",
			input:    0x6401a8c0,
			expected: netip.MustParseAddr("192.168.1.100"),
		},
		{
			name:     "172.18.0.4",
			input:    0x040012ac,
			expected: netip.MustParseAddr("172.18.0.4"),
		},
		{
			name:     "zero address",
			input:    0x00000000,
			expected: netip.MustParseAddr("0.0.0.0"),
		},
		{
			name:     "broadcast 255.255.255.255",
			input:    0xffffffff,
			expected: netip.MustParseAddr("255.255.255.255"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := addrFromKernelIPv4(tt.input)
			if got != tt.expected {
				t.Errorf("addrFromKernelIPv4(0x%08x) = %s, want %s", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDecodeDirection(t *testing.T) {
	tests := []struct {
		input    uint8
		expected netwatch.Direction
	}{
		{0, netwatch.Ingress},
		{1, netwatch.Egress},
		{2, netwatch.Ingress},
		{255, netwatch.Ingress},
	}

	for _, tt := range tests {
		got := decodeDirection(tt.input)
		if got != tt.expected {
			t.Errorf("decodeDirection(%d) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestDecodeProtocol(t *testing.T) {
	tests := []struct {
		input    uint8
		expected netwatch.Protocol
	}{
		{6, netwatch.ProtocolTCP},
		{17, netwatch.ProtocolUDP},
		{0, netwatch.ProtocolUnknown},
		{1, netwatch.ProtocolUnknown},
		{255, netwatch.ProtocolUnknown},
	}

	for _, tt := range tests {
		got := decodeProtocol(tt.input)
		if got != tt.expected {
			t.Errorf("decodeProtocol(%d) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestSumPerCPU(t *testing.T) {
	tests := []struct {
		name            string
		values          []netwatchTrafficValue
		expectedBytes   uint64
		expectedPackets uint64
	}{
		{
			name:            "empty slice",
			values:          nil,
			expectedBytes:   0,
			expectedPackets: 0,
		},
		{
			name:            "single CPU",
			values:          []netwatchTrafficValue{{Bytes: 1000, Packets: 10}},
			expectedBytes:   1000,
			expectedPackets: 10,
		},
		{
			name: "four CPUs",
			values: []netwatchTrafficValue{
				{Bytes: 100, Packets: 1},
				{Bytes: 200, Packets: 2},
				{Bytes: 300, Packets: 3},
				{Bytes: 400, Packets: 4},
			},
			expectedBytes:   1000,
			expectedPackets: 10,
		},
		{
			name: "some CPUs idle",
			values: []netwatchTrafficValue{
				{Bytes: 500, Packets: 5},
				{Bytes: 0, Packets: 0},
				{Bytes: 0, Packets: 0},
				{Bytes: 500, Packets: 5},
			},
			expectedBytes:   1000,
			expectedPackets: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBytes, gotPackets := sumPerCPU(tt.values)
			if gotBytes != tt.expectedBytes || gotPackets != tt.expectedPackets {
				t.Errorf("sumPerCPU() = (%d, %d), want (%d, %d)",
					gotBytes, gotPackets, tt.expectedBytes, tt.expectedPackets)
			}
		})
	}
}

func TestDecodeSample(t *testing.T) {
	ts := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	key := netwatchTrafficKey{
		CgroupId:  42,
		RemoteIp4: 0x040012ac, // 172.18.0.4
		Direction: 1,          // egress
		Protocol:  6,          // TCP
	}
	values := []netwatchTrafficValue{
		{Bytes: 1000, Packets: 10},
		{Bytes: 2000, Packets: 20},
	}

	sample := decodeSample(key, values, ts)

	if sample.CgroupID != 42 {
		t.Errorf("CgroupID = %d, want 42", sample.CgroupID)
	}
	if sample.Direction != netwatch.Egress {
		t.Errorf("Direction = %v, want Egress", sample.Direction)
	}
	if sample.Remote.Protocol != netwatch.ProtocolTCP {
		t.Errorf("Protocol = %v, want TCP", sample.Remote.Protocol)
	}

	expectedAddr := netip.MustParseAddr("172.18.0.4")
	if sample.Remote.Addr != expectedAddr {
		t.Errorf("Remote.Addr = %s, want %s", sample.Remote.Addr, expectedAddr)
	}
	if sample.Bytes != 3000 {
		t.Errorf("Bytes = %d, want 3000", sample.Bytes)
	}
	if sample.Packets != 30 {
		t.Errorf("Packets = %d, want 30", sample.Packets)
	}
	if sample.Timestamp != ts {
		t.Errorf("Timestamp = %v, want %v", sample.Timestamp, ts)
	}
}

func TestDecodeSampleIngress(t *testing.T) {
	ts := time.Now()

	key := netwatchTrafficKey{
		CgroupId:  99,
		RemoteIp4: 0x0100007f, // 127.0.0.1
		Direction: 0,          // ingress
		Protocol:  17,         // UDP
	}
	values := []netwatchTrafficValue{
		{Bytes: 512, Packets: 1},
	}

	sample := decodeSample(key, values, ts)

	if sample.Direction != netwatch.Ingress {
		t.Errorf("Direction = %v, want Ingress", sample.Direction)
	}
	if sample.Remote.Protocol != netwatch.ProtocolUDP {
		t.Errorf("Protocol = %v, want UDP", sample.Remote.Protocol)
	}
	if sample.Remote.Addr != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("Remote.Addr = %s, want 127.0.0.1", sample.Remote.Addr)
	}
}

func TestDecodeSampleUnknownProtocol(t *testing.T) {
	ts := time.Now()

	key := netwatchTrafficKey{
		CgroupId:  1,
		RemoteIp4: 0x0100000a, // 10.0.0.1
		Direction: 0,
		Protocol:  47, // GRE — not TCP or UDP
	}
	values := []netwatchTrafficValue{
		{Bytes: 100, Packets: 1},
	}

	sample := decodeSample(key, values, ts)

	if sample.Remote.Protocol != netwatch.ProtocolUnknown {
		t.Errorf("Protocol = %v, want Unknown", sample.Remote.Protocol)
	}
}
