package simpleaggregator

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"docker-net-ebpf/netwatch"
)

type Aggregator struct {
	resolver netwatch.Resolver
	previous map[trafficCounterKey]previousCounter
}

type trafficCounterKey struct {
	CgroupID  uint64
	Direction netwatch.Direction
	Addr      netip.Addr
	Protocol  netwatch.Protocol
}

type trafficGroupKey struct {
	CgroupID uint64
	Addr     netip.Addr
	Protocol netwatch.Protocol
}

type previousCounter struct {
	Bytes     uint64
	Packets   uint64
	Timestamp time.Time
}

func New(resolver netwatch.Resolver) *Aggregator {
	return &Aggregator{
		resolver: resolver,
		previous: make(map[trafficCounterKey]previousCounter),
	}
}

func (a *Aggregator) Aggregate(raw []netwatch.RawTrafficSample) ([]netwatch.TrafficSample, error) {
	totals := make(map[trafficGroupKey]*netwatch.TrafficSample)
	current := make(map[trafficCounterKey]previousCounter, len(raw))

	for _, sample := range raw {
		container, err := a.resolver.Resolve(context.Background(), sample.CgroupID)
		if err != nil {
			continue
		}

		counterKey := trafficCounterKey{
			CgroupID:  sample.CgroupID,
			Direction: sample.Direction,
			Addr:      sample.Remote.Addr,
			Protocol:  sample.Remote.Protocol,
		}

		groupKey := trafficGroupKey{
			CgroupID: sample.CgroupID,
			Addr:     sample.Remote.Addr,
			Protocol: sample.Remote.Protocol,
		}

		traffic := totals[groupKey]
		if traffic == nil {
			traffic = &netwatch.TrafficSample{
				Timestamp: sample.Timestamp,
				Container: container,
				Remote:    sample.Remote,
			}
			totals[groupKey] = traffic
		} else if sample.Timestamp.After(traffic.Timestamp) {
			traffic.Timestamp = sample.Timestamp
		}

		prev, seen := a.previous[counterKey]
		bytesDelta := sample.Bytes
		packetsDelta := sample.Packets
		interval := time.Duration(0)
		if seen {
			interval = sample.Timestamp.Sub(prev.Timestamp)
			if sample.Bytes >= prev.Bytes {
				bytesDelta = sample.Bytes - prev.Bytes
			}
			if sample.Packets >= prev.Packets {
				packetsDelta = sample.Packets - prev.Packets
			}
		}
		if interval > traffic.Interval {
			traffic.Interval = interval
		}

		switch sample.Direction {
		case netwatch.Ingress:
			traffic.RxBytesTotal += sample.Bytes
			traffic.RxPacketsTotal += sample.Packets
			traffic.RxBytesDelta += bytesDeltaIfSeen(seen, bytesDelta)
			traffic.RxPacketsDelta += packetsDeltaIfSeen(seen, packetsDelta)
		case netwatch.Egress:
			traffic.TxBytesTotal += sample.Bytes
			traffic.TxPacketsTotal += sample.Packets
			traffic.TxBytesDelta += bytesDeltaIfSeen(seen, bytesDelta)
			traffic.TxPacketsDelta += packetsDeltaIfSeen(seen, packetsDelta)
		}

		current[counterKey] = previousCounter{
			Bytes:     sample.Bytes,
			Packets:   sample.Packets,
			Timestamp: sample.Timestamp,
		}
	}

	a.previous = current

	results := make([]netwatch.TrafficSample, 0, len(totals))
	for _, sample := range totals {
		results = append(results, *sample)
	}

	sort.Slice(results, func(i, j int) bool {
		left := results[i].RxBytesTotal + results[i].TxBytesTotal
		right := results[j].RxBytesTotal + results[j].TxBytesTotal
		return left > right
	})

	return results, nil
}

func (a *Aggregator) Reset() {
	a.previous = make(map[trafficCounterKey]previousCounter)
}

func bytesDeltaIfSeen(seen bool, delta uint64) uint64 {
	if !seen {
		return 0
	}
	return delta
}

func packetsDeltaIfSeen(seen bool, delta uint64) uint64 {
	if !seen {
		return 0
	}
	return delta
}
