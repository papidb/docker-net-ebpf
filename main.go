package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" netwatch ./bpf/netwatch.bpf.c -- -I/usr/include -I/usr/include/aarch64-linux-gnu

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"docker-net-ebpf/netwatch"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type dockerResolver struct {
	containers map[uint64]netwatch.ContainerInfo
}

type ebpfCollector struct {
	objs  netwatchObjects
	links map[uint64][]link.Link
}

type simpleAggregator struct {
	resolver netwatch.Resolver
}

type consoleOutput struct{}

type trafficGroupKey struct {
	CgroupID  uint64
	Direction netwatch.Direction
	Addr      netip.Addr
	Protocol  netwatch.Protocol
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("run with sudo")
	}

	ctx := context.Background()

	resolver := &dockerResolver{}
	containers, err := resolver.Discover(ctx)
	if err != nil {
		log.Fatal(err)
	}

	if len(containers) == 0 {
		log.Fatal("no docker container cgroups found")
	}

	collector, err := newEBPFCollector()
	if err != nil {
		log.Fatal(err)
	}
	defer collector.Close()

	for _, container := range containers {
		if err := collector.Attach(ctx, container); err != nil {
			log.Printf("attach %s: %v", container.Name, err)
			continue
		}

		fmt.Printf("attached: %-30s cgroup_id=%d path=%s\n", container.Name, container.CgroupID, container.CgroupPath)
	}

	aggregator := simpleAggregator{resolver: resolver}
	output := consoleOutput{}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		raw, err := collector.Collect(ctx)
		if err != nil {
			log.Printf("collect: %v", err)
			continue
		}

		samples, err := aggregator.Aggregate(raw)
		if err != nil {
			log.Printf("aggregate: %v", err)
			continue
		}

		if err := output.Write(ctx, samples); err != nil {
			log.Printf("write output: %v", err)
		}
	}
}

func newEBPFCollector() (*ebpfCollector, error) {
	collector := &ebpfCollector{links: make(map[uint64][]link.Link)}

	if err := loadNetwatchObjects(&collector.objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	return collector, nil
}

func (c *ebpfCollector) Attach(_ context.Context, container netwatch.ContainerInfo) error {
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

func (c *ebpfCollector) Detach(_ context.Context, container netwatch.ContainerInfo) error {
	for _, l := range c.links[container.CgroupID] {
		if err := l.Close(); err != nil {
			return err
		}
	}

	delete(c.links, container.CgroupID)
	return nil
}

func (c *ebpfCollector) Collect(_ context.Context) ([]netwatch.RawTrafficSample, error) {
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

func (c *ebpfCollector) Close() error {
	for _, links := range c.links {
		for _, l := range links {
			if err := l.Close(); err != nil {
				return err
			}
		}
	}

	return c.objs.Close()
}

func (r *dockerResolver) Discover(_ context.Context) ([]netwatch.ContainerInfo, error) {
	targets, err := discoverDockerCgroups()
	if err != nil {
		return nil, err
	}

	r.containers = make(map[uint64]netwatch.ContainerInfo, len(targets))
	containers := make([]netwatch.ContainerInfo, 0, len(targets))

	for _, target := range targets {
		container := netwatch.ContainerInfo{
			ID:         target.ID,
			Name:       target.Name,
			CgroupID:   target.CgroupID,
			CgroupPath: target.CgroupPath,
			Runtime:    "docker",
		}

		r.containers[target.CgroupID] = container
		containers = append(containers, container)
	}

	return containers, nil
}

func (r *dockerResolver) Resolve(_ context.Context, cgroupID uint64) (netwatch.ContainerInfo, error) {
	container, ok := r.containers[cgroupID]
	if !ok {
		return netwatch.ContainerInfo{}, fmt.Errorf("container for cgroup %d not found", cgroupID)
	}

	return container, nil
}

func (a simpleAggregator) Aggregate(raw []netwatch.RawTrafficSample) ([]netwatch.TrafficSample, error) {
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

func (a simpleAggregator) Reset() {}

func (consoleOutput) Write(_ context.Context, samples []netwatch.TrafficSample) error {
	hasDestinations := false
	for _, sample := range samples {
		if sample.Remote.Addr.IsValid() {
			hasDestinations = true
			break
		}
	}

	fmt.Print("\033[H\033[2J")
	if hasDestinations {
		fmt.Println("Docker network destinations from eBPF cgroup_skb")
		fmt.Println(strings.Repeat("-", 136))
		fmt.Printf("%-24s %-14s %-8s %-22s %-8s %-15s %-15s %-15s\n", "CONTAINER", "ID", "DIR", "REMOTE IP", "PROTO", "RX", "TX", "TOTAL")
		fmt.Println(strings.Repeat("-", 136))
	} else {
		fmt.Println("Docker network usage from eBPF cgroup_skb")
		fmt.Println(strings.Repeat("-", 100))
		fmt.Printf("%-30s %-15s %-15s %-15s %-15s\n", "CONTAINER", "ID", "RX", "TX", "TOTAL")
		fmt.Println(strings.Repeat("-", 100))
	}

	for _, sample := range samples {
		total := sample.RxBytesTotal + sample.TxBytesTotal
		if hasDestinations {
			fmt.Printf(
				"%-24s %-14s %-8s %-22s %-8s %-15s %-15s %-15s\n",
				sample.Container.Name,
				shortID(sample.Container.ID),
				directionLabel(sample),
				endpointLabel(sample.Remote),
				sample.Remote.Protocol.String(),
				humanBytes(sample.RxBytesTotal),
				humanBytes(sample.TxBytesTotal),
				humanBytes(total),
			)
			continue
		}

		fmt.Printf(
			"%-30s %-15s %-15s %-15s %-15s\n",
			sample.Container.Name,
			shortID(sample.Container.ID),
			humanBytes(sample.RxBytesTotal),
			humanBytes(sample.TxBytesTotal),
			humanBytes(total),
		)
	}

	return nil
}

func (consoleOutput) Close() error {
	return nil
}

func discoverDockerCgroups() ([]netwatch.ContainerInfo, error) {
	out, err := exec.Command(
		"docker",
		"ps",
		"--format",
		"{{.ID}} {{.Names}}",
	).Output()
	if err != nil {
		return nil, err
	}

	var containers []netwatch.ContainerInfo
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		id := parts[0]
		name := parts[1]
		path, err := findCgroupPath(id)
		if err != nil {
			log.Printf("could not find cgroup for %s: %v", name, err)
			continue
		}

		cgroupID, err := cgroupID(path)
		if err != nil {
			log.Printf("could not stat cgroup for %s: %v", name, err)
			continue
		}

		containers = append(containers, netwatch.ContainerInfo{
			ID:         id,
			Name:       name,
			CgroupID:   cgroupID,
			CgroupPath: path,
			Runtime:    "docker",
		})
	}

	return containers, nil
}

func findCgroupPath(containerID string) (string, error) {
	root := "/sys/fs/cgroup"
	var found string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}

		base := filepath.Base(path)
		if strings.Contains(base, containerID) || strings.Contains(path, containerID) {
			found = path
			return filepath.SkipAll
		}

		return nil
	})
	if err != nil {
		return "", err
	}

	if found == "" {
		return "", fmt.Errorf("not found")
	}

	return found, nil
}

func cgroupID(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}

	return st.Ino, nil
}

func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}

	return id[:12]
}

func endpointLabel(endpoint netwatch.Endpoint) string {
	if !endpoint.Addr.IsValid() {
		return "-"
	}

	return endpoint.Addr.String()
}

func directionLabel(sample netwatch.TrafficSample) string {
	switch {
	case sample.TxBytesTotal > 0 && sample.RxBytesTotal == 0:
		return netwatch.Egress.String()
	case sample.RxBytesTotal > 0 && sample.TxBytesTotal == 0:
		return netwatch.Ingress.String()
	case sample.RxBytesTotal == 0 && sample.TxBytesTotal == 0:
		return "unknown"
	default:
		return "mixed"
	}
}

func addrFromKernelIPv4(value uint32) netip.Addr {
	var bytes [4]byte
	bytes[0] = byte(value)
	bytes[1] = byte(value >> 8)
	bytes[2] = byte(value >> 16)
	bytes[3] = byte(value >> 24)
	return netip.AddrFrom4(bytes)
}

func humanBytes(bytes uint64) string {
	const unit = 1024

	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}

	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f%ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
