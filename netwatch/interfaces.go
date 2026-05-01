package netwatch

import "context"

// Collector reads raw traffic counters from the kernel.
type Collector interface {
	// Collect returns the current cumulative counters for all tracked cgroups.
	Collect(ctx context.Context) ([]RawTrafficSample, error)

	// Attach starts tracking the given container's cgroup.
	Attach(ctx context.Context, container ContainerInfo) error

	// Detach stops tracking the given container's cgroup.
	Detach(ctx context.Context, container ContainerInfo) error

	// Close releases all eBPF resources.
	Close() error
}

// Resolver maps low-level cgroup identifiers to container metadata.
type Resolver interface {
	// Resolve looks up container info for a given cgroup ID.
	Resolve(ctx context.Context, cgroupID uint64) (ContainerInfo, error)

	// Discover returns all currently running containers.
	Discover(ctx context.Context) ([]ContainerInfo, error)
}

// Aggregator computes deltas, rates, and handles counter resets.
type Aggregator interface {
	// Aggregate takes raw cumulative samples and returns delta-computed traffic samples.
	Aggregate(raw []RawTrafficSample) ([]TrafficSample, error)

	// Reset clears internal state (previous counters).
	Reset()
}

// Output receives processed traffic samples for persistence or export.
type Output interface {
	// Write handles a batch of traffic samples.
	Write(ctx context.Context, samples []TrafficSample) error

	// Close flushes and releases output resources.
	Close() error
}
