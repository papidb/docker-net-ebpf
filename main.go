package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	simpleaggregator "docker-net-ebpf/internal/aggregator/simple"
	ebpfcollector "docker-net-ebpf/internal/collector/ebpf"
	consoleoutput "docker-net-ebpf/internal/output/console"
	dockerresolver "docker-net-ebpf/internal/resolver/docker"
)

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("run with sudo")
	}

	ctx := context.Background()

	resolver := dockerresolver.New()
	containers, err := resolver.Discover(ctx)
	if err != nil {
		log.Fatal(err)
	}

	if len(containers) == 0 {
		log.Fatal("no docker container cgroups found")
	}

	collector, err := ebpfcollector.New()
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

	aggregator := simpleaggregator.New(resolver)
	output := consoleoutput.New()

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
