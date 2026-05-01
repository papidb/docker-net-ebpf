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
		return fmt.Errorf(strings.Join(attachErrs, "; "))
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
		var total netwatchTrafficValue

		for _, value := range values {
			total.Bytes += value.Bytes
			total.Packets += value.Packets
		}

		direction := netwatch.Ingress
		if key.Direction == 1 {
			direction = netwatch.Egress
		}

		protocol := netwatch.ProtocolUnknown
		switch key.Protocol {
		case uint8(netwatch.ProtocolTCP):
			protocol = netwatch.ProtocolTCP
		case uint8(netwatch.ProtocolUDP):
			protocol = netwatch.ProtocolUDP
		}

		samples = append(samples, netwatch.RawTrafficSample{
			CgroupID:  key.CgroupId,
			Direction: direction,
			Remote: netwatch.Endpoint{
				Addr:     addrFromKernelIPv4(key.RemoteIp4),
				Protocol: protocol,
			},
			Bytes:     total.Bytes,
			Packets:   total.Packets,
			Timestamp: now,
		})
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return samples, nil
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
