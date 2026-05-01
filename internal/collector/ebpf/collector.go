package ebpfcollector

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"docker-net-ebpf/netwatch"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Collector struct {
	objs  netwatchObjects
	links map[uint64][]link.Link
}

func New() (*Collector, error) {
	collector := &Collector{links: make(map[uint64][]link.Link)}
	if err := loadNetwatchObjects(&collector.objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}
	return collector, nil
}

func (c *Collector) Attach(_ context.Context, container netwatch.ContainerInfo) error {
	var attached []link.Link
	var attachErrs []string

	ingress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    container.CgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: c.objs.CountIngress,
	})
	if err != nil {
		attachErrs = append(attachErrs, fmt.Sprintf("ingress: %v", err))
	} else {
		attached = append(attached, ingress)
	}

	egress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    container.CgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: c.objs.CountEgress,
	})
	if err != nil {
		attachErrs = append(attachErrs, fmt.Sprintf("egress: %v", err))
	} else {
		attached = append(attached, egress)
	}

	if len(attached) > 0 {
		c.links[container.CgroupID] = append(c.links[container.CgroupID], attached...)
	}

	if len(attachErrs) > 0 {
		return fmt.Errorf("attach failed: %s", strings.Join(attachErrs, "; "))
	}

	return nil
}

func (c *Collector) Detach(_ context.Context, container netwatch.ContainerInfo) error {
	for _, l := range c.links[container.CgroupID] {
		if err := l.Close(); err != nil {
			return err
		}
	}

	delete(c.links, container.CgroupID)
	return nil
}

func (c *Collector) Collect(_ context.Context) ([]netwatch.RawTrafficSample, error) {
	var key netwatchTrafficKey
	var values []netwatchTrafficValue

	now := time.Now()
	iter := c.objs.Stats.Iterate()
	samples := make([]netwatch.RawTrafficSample, 0)

	for iter.Next(&key, &values) {
		samples = append(samples, decodeSample(key, values, now))
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return samples, nil
}

func decodeSample(key netwatchTrafficKey, perCPUValues []netwatchTrafficValue, ts time.Time) netwatch.RawTrafficSample {
	totalBytes, totalPackets := sumPerCPU(perCPUValues)

	return netwatch.RawTrafficSample{
		CgroupID:  key.CgroupId,
		Direction: decodeDirection(key.Direction),
		Remote: netwatch.Endpoint{
			Addr:     addrFromKernelIPv4(key.RemoteIp4),
			Protocol: decodeProtocol(key.Protocol),
		},
		Bytes:     totalBytes,
		Packets:   totalPackets,
		Timestamp: ts,
	}
}

func sumPerCPU(values []netwatchTrafficValue) (bytes, packets uint64) {
	for _, v := range values {
		bytes += v.Bytes
		packets += v.Packets
	}
	return
}

func decodeDirection(raw uint8) netwatch.Direction {
	if raw == 1 {
		return netwatch.Egress
	}
	return netwatch.Ingress
}

func decodeProtocol(raw uint8) netwatch.Protocol {
	switch raw {
	case uint8(netwatch.ProtocolTCP):
		return netwatch.ProtocolTCP
	case uint8(netwatch.ProtocolUDP):
		return netwatch.ProtocolUDP
	default:
		return netwatch.ProtocolUnknown
	}
}

func (c *Collector) Close() error {
	for _, links := range c.links {
		for _, l := range links {
			if err := l.Close(); err != nil {
				return err
			}
		}
	}

	return c.objs.Close()
}

func addrFromKernelIPv4(value uint32) netip.Addr {
	var bytes [4]byte
	bytes[0] = byte(value)
	bytes[1] = byte(value >> 8)
	bytes[2] = byte(value >> 16)
	bytes[3] = byte(value >> 24)
	return netip.AddrFrom4(bytes)
}
