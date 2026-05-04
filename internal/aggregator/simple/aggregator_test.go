package simpleaggregator

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"docker-net-ebpf/netwatch"
)

func TestAggregateFirstSampleEmitsZeroDelta(t *testing.T) {
	t.Parallel()

	agg := New(staticResolver())
	now := time.Unix(1_700_000_000, 0).UTC()

	samples, err := agg.Aggregate([]netwatch.RawTrafficSample{
		rawSample(now, netwatch.Ingress, 100, 10),
		rawSample(now, netwatch.Egress, 200, 20),
	})
	if err != nil {
		t.Fatalf("Aggregate returned error: %v", err)
	}

	if len(samples) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(samples))
	}

	got := samples[0]
	if got.RxBytesDelta != 0 || got.TxBytesDelta != 0 || got.RxPacketsDelta != 0 || got.TxPacketsDelta != 0 {
		t.Fatalf("expected zero deltas on first sample, got %#v", got)
	}
	if got.RxBytesTotal != 100 || got.TxBytesTotal != 200 || got.RxPacketsTotal != 10 || got.TxPacketsTotal != 20 {
		t.Fatalf("unexpected totals on first sample: %#v", got)
	}
	if got.Interval != 0 {
		t.Fatalf("expected zero interval on first sample, got %s", got.Interval)
	}
}

func TestAggregateComputesDeltaAndInterval(t *testing.T) {
	t.Parallel()

	agg := New(staticResolver())
	start := time.Unix(1_700_000_000, 0).UTC()
	next := start.Add(2 * time.Second)

	_, err := agg.Aggregate([]netwatch.RawTrafficSample{
		rawSample(start, netwatch.Ingress, 100, 10),
		rawSample(start, netwatch.Egress, 200, 20),
	})
	if err != nil {
		t.Fatalf("initial Aggregate returned error: %v", err)
	}

	samples, err := agg.Aggregate([]netwatch.RawTrafficSample{
		rawSample(next, netwatch.Ingress, 160, 16),
		rawSample(next, netwatch.Egress, 260, 24),
	})
	if err != nil {
		t.Fatalf("second Aggregate returned error: %v", err)
	}

	if len(samples) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(samples))
	}

	got := samples[0]
	if got.RxBytesDelta != 60 || got.TxBytesDelta != 60 || got.RxPacketsDelta != 6 || got.TxPacketsDelta != 4 {
		t.Fatalf("unexpected deltas: %#v", got)
	}
	if got.RxBytesTotal != 160 || got.TxBytesTotal != 260 || got.RxPacketsTotal != 16 || got.TxPacketsTotal != 24 {
		t.Fatalf("unexpected totals: %#v", got)
	}
	if got.Interval != 2*time.Second {
		t.Fatalf("expected 2s interval, got %s", got.Interval)
	}
}

func TestAggregateTreatsCounterDecreaseAsReset(t *testing.T) {
	t.Parallel()

	agg := New(staticResolver())
	start := time.Unix(1_700_000_000, 0).UTC()
	next := start.Add(2 * time.Second)

	_, err := agg.Aggregate([]netwatch.RawTrafficSample{
		rawSample(start, netwatch.Ingress, 100, 10),
		rawSample(start, netwatch.Egress, 200, 20),
	})
	if err != nil {
		t.Fatalf("initial Aggregate returned error: %v", err)
	}

	samples, err := agg.Aggregate([]netwatch.RawTrafficSample{
		rawSample(next, netwatch.Ingress, 25, 3),
		rawSample(next, netwatch.Egress, 40, 5),
	})
	if err != nil {
		t.Fatalf("reset Aggregate returned error: %v", err)
	}

	got := samples[0]
	if got.RxBytesDelta != 25 || got.TxBytesDelta != 40 || got.RxPacketsDelta != 3 || got.TxPacketsDelta != 5 {
		t.Fatalf("expected reset deltas to equal current values, got %#v", got)
	}
	if got.Interval != 2*time.Second {
		t.Fatalf("expected 2s interval after reset, got %s", got.Interval)
	}
}

func TestResetClearsPreviousState(t *testing.T) {
	t.Parallel()

	agg := New(staticResolver())
	start := time.Unix(1_700_000_000, 0).UTC()
	next := start.Add(2 * time.Second)

	_, err := agg.Aggregate([]netwatch.RawTrafficSample{rawSample(start, netwatch.Egress, 200, 20)})
	if err != nil {
		t.Fatalf("initial Aggregate returned error: %v", err)
	}

	agg.Reset()

	samples, err := agg.Aggregate([]netwatch.RawTrafficSample{rawSample(next, netwatch.Egress, 260, 24)})
	if err != nil {
		t.Fatalf("Aggregate after Reset returned error: %v", err)
	}

	got := samples[0]
	if got.TxBytesDelta != 0 || got.TxPacketsDelta != 0 {
		t.Fatalf("expected zero delta after Reset, got %#v", got)
	}
}

type fakeResolver struct {
	container netwatch.ContainerInfo
}

func staticResolver() *fakeResolver {
	return &fakeResolver{
		container: netwatch.ContainerInfo{
			ID:       "abc123",
			Name:     "lab-egress",
			CgroupID: 7,
			Runtime:  "docker",
		},
	}
}

func (r *fakeResolver) Resolve(_ context.Context, cgroupID uint64) (netwatch.ContainerInfo, error) {
	container := r.container
	container.CgroupID = cgroupID
	return container, nil
}

func (r *fakeResolver) Discover(_ context.Context) ([]netwatch.ContainerInfo, error) {
	return []netwatch.ContainerInfo{r.container}, nil
}

func rawSample(ts time.Time, direction netwatch.Direction, bytes uint64, packets uint64) netwatch.RawTrafficSample {
	return netwatch.RawTrafficSample{
		CgroupID:  7,
		Direction: direction,
		Remote: netwatch.Endpoint{
			Addr:     netip.MustParseAddr("162.159.140.220"),
			Protocol: netwatch.ProtocolTCP,
		},
		Bytes:     bytes,
		Packets:   packets,
		Timestamp: ts,
	}
}
