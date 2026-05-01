package simpleaggregator

import (
	"context"
	"net/netip"
	"sort"

	"docker-net-ebpf/netwatch"
)

type Aggregator struct {
	resolver netwatch.Resolver
}

type trafficGroupKey struct {
	CgroupID  uint64
	Direction netwatch.Direction
	Addr      netip.Addr
	Protocol  netwatch.Protocol
}

func New(resolver netwatch.Resolver) *Aggregator {
	return &Aggregator{resolver: resolver}
}

func (a *Aggregator) Aggregate(raw []netwatch.RawTrafficSample) ([]netwatch.TrafficSample, error) {
	totals := make(map[trafficGroupKey]*netwatch.TrafficSample)

	for _, sample := range raw {
		container, err := a.resolver.Resolve(context.Background(), sample.CgroupID)
		if err != nil {
			continue
		}

		key := trafficGroupKey{
			CgroupID:  sample.CgroupID,
			Direction: sample.Direction,
			Addr:      sample.Remote.Addr,
			Protocol:  sample.Remote.Protocol,
		}

		traffic := totals[key]
		if traffic == nil {
			traffic = &netwatch.TrafficSample{
				Timestamp: sample.Timestamp,
				Container: container,
				Remote:    sample.Remote,
			}
			totals[key] = traffic
		}

		switch sample.Direction {
		case netwatch.Ingress:
			traffic.RxBytesTotal += sample.Bytes
			traffic.RxPacketsTotal += sample.Packets
		case netwatch.Egress:
			traffic.TxBytesTotal += sample.Bytes
			traffic.TxPacketsTotal += sample.Packets
		}
	}

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

func (a *Aggregator) Reset() {}
