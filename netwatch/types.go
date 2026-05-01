package netwatch

import (
	"net/netip"
	"time"
)

// Direction represents the traffic direction relative to the container.
type Direction uint8

const (
	Ingress Direction = 0
	Egress  Direction = 1
)

func (d Direction) String() string {
	switch d {
	case Ingress:
		return "ingress"
	case Egress:
		return "egress"
	default:
		return "unknown"
	}
}

// Protocol represents the network protocol carried by a sample.
type Protocol uint8

const (
	ProtocolUnknown Protocol = 0
	ProtocolTCP     Protocol = 6
	ProtocolUDP     Protocol = 17
)

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	default:
		return "unknown"
	}
}

// Endpoint identifies the remote network location associated with traffic.
type Endpoint struct {
	Addr     netip.Addr
	Protocol Protocol
}

// ContainerInfo holds the resolved identity of a container.
type ContainerInfo struct {
	ID         string
	Name       string
	CgroupID   uint64
	CgroupPath string
	Runtime    string // "docker", "containerd", "podman", etc.
}

// RawTrafficSample is a single kernel-level measurement from eBPF.
// Counters are cumulative since the eBPF program was attached.
type RawTrafficSample struct {
	CgroupID  uint64
	Direction Direction
	Remote    Endpoint
	Bytes     uint64
	Packets   uint64
	Timestamp time.Time
}

// TrafficSample is the normalized, delta-computed output of the aggregator.
// This is the core data contract of the system.
type TrafficSample struct {
	Timestamp time.Time
	Interval  time.Duration

	Container ContainerInfo
	Remote    Endpoint

	RxBytesDelta   uint64
	TxBytesDelta   uint64
	RxPacketsDelta uint64
	TxPacketsDelta uint64

	RxBytesTotal uint64
	TxBytesTotal uint64
	RxPacketsTotal uint64
	TxPacketsTotal uint64
}

// Snapshot is a point-in-time collection of all container traffic samples.
type Snapshot struct {
	Timestamp time.Time
	Samples   []TrafficSample
}
