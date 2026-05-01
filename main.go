package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" netwatch ./bpf/netwatch.bpf.c -- -I/usr/include

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"golang.org/x/sys/unix"
)

const (
	dirIngress uint8 = 0
	dirEgress  uint8 = 1
)

type trafficKey struct {
	CgroupID  uint64
	Direction uint8
	Pad       [7]byte
}

type trafficValue struct {
	Bytes   uint64
	Packets uint64
}

type containerTarget struct {
	ID         string
	Name       string
	CgroupID   uint64
	CgroupPath string
}

type aggregate struct {
	Name      string
	ID        string
	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("run with sudo")
	}

	ctx := context.Background()

	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		log.Fatal(err)
	}

	targets, err := discoverDockerCgroups(ctx, cli)
	if err != nil {
		log.Fatal(err)
	}

	if len(targets) == 0 {
		log.Fatal("no docker container cgroups found")
	}

	var objs netwatchObjects
	if err := loadNetwatchObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	for _, t := range targets {
		ingress, err := link.AttachCgroup(link.CgroupOptions{
			Path:    t.CgroupPath,
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: objs.CountIngress,
		})
		if err != nil {
			log.Printf("failed attaching ingress to %s: %v", t.Name, err)
		} else {
			links = append(links, ingress)
		}

		egress, err := link.AttachCgroup(link.CgroupOptions{
			Path:    t.CgroupPath,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: objs.CountEgress,
		})
		if err != nil {
			log.Printf("failed attaching egress to %s: %v", t.Name, err)
		} else {
			links = append(links, egress)
		}

		fmt.Printf("attached: %-30s cgroup_id=%d path=%s\n", t.Name, t.CgroupID, t.CgroupPath)
	}

	cgroupToContainer := map[uint64]containerTarget{}
	for _, t := range targets {
		cgroupToContainer[t.CgroupID] = t
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		results, err := readStats(objs.Stats, cgroupToContainer)
		if err != nil {
			log.Printf("read stats: %v", err)
			continue
		}

		printTable(results)
	}
}

func discoverDockerCgroups(ctx context.Context, cli *client.Client) ([]containerTarget, error) {
	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, err
	}

	var targets []containerTarget

	for _, c := range containers {
		name := shortID(c.ID)
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		path, err := findCgroupPath(c.ID)
		if err != nil {
			log.Printf("could not find cgroup for %s: %v", name, err)
			continue
		}

		cgid, err := cgroupID(path)
		if err != nil {
			log.Printf("could not stat cgroup for %s: %v", name, err)
			continue
		}

		targets = append(targets, containerTarget{
			ID:         shortID(c.ID),
			Name:       name,
			CgroupID:   cgid,
			CgroupPath: path,
		})
	}

	return targets, nil
}

func findCgroupPath(containerID string) (string, error) {
	root := "/sys/fs/cgroup"

	var found string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if !d.IsDir() {
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

func readStats(statsMap *ebpf.Map, cgroups map[uint64]containerTarget) ([]aggregate, error) {
	out := map[uint64]*aggregate{}

	var key trafficKey
	var values []trafficValue

	iter := statsMap.Iterate()

	for iter.Next(&key, &values) {
		var total trafficValue

		for _, v := range values {
			total.Bytes += v.Bytes
			total.Packets += v.Packets
		}

		target, ok := cgroups[key.CgroupID]
		if !ok {
			continue
		}

		if _, ok := out[key.CgroupID]; !ok {
			out[key.CgroupID] = &aggregate{
				Name: target.Name,
				ID:   target.ID,
			}
		}

		switch key.Direction {
		case dirIngress:
			out[key.CgroupID].RxBytes += total.Bytes
			out[key.CgroupID].RxPackets += total.Packets
		case dirEgress:
			out[key.CgroupID].TxBytes += total.Bytes
			out[key.CgroupID].TxPackets += total.Packets
		}
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	var results []aggregate
	for _, r := range out {
		results = append(results, *r)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].TxBytes+results[i].RxBytes > results[j].TxBytes+results[j].RxBytes
	})

	return results, nil
}

func printTable(results []aggregate) {
	fmt.Print("\033[H\033[2J")
	fmt.Println("Docker network usage from eBPF cgroup_skb")
	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("%-30s %-15s %-15s %-15s %-15s\n", "CONTAINER", "ID", "RX", "TX", "TOTAL")
	fmt.Println(strings.Repeat("-", 100))

	for _, r := range results {
		total := r.RxBytes + r.TxBytes

		fmt.Printf(
			"%-30s %-15s %-15s %-15s %-15s\n",
			r.Name,
			r.ID,
			humanBytes(r.RxBytes),
			humanBytes(r.TxBytes),
			humanBytes(total),
		)
	}
}

func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}

	return id[:12]
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
