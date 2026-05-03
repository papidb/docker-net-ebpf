package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	simpleaggregator "docker-net-ebpf/internal/aggregator/simple"
	ebpfcollector "docker-net-ebpf/internal/collector/ebpf"
	"docker-net-ebpf/internal/doctor"
	consoleoutput "docker-net-ebpf/internal/output/console"
	dockerresolver "docker-net-ebpf/internal/resolver/docker"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "docker-net-ebpf",
		Short: "Container network observability using eBPF",
	}

	root.AddCommand(doctorCmd())
	root.AddCommand(watchCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check environment readiness (kernel, cgroup, BPF, Docker)",
		RunE: func(cmd *cobra.Command, args []string) error {
			results := doctor.Checks(cmd.Context())
			for _, result := range results {
				printDoctorResult(result)
			}

			failures := doctor.FailureCount(results)
			if failures > 0 {
				return fmt.Errorf("doctor failed: %d check(s) failed", failures)
			}

			fmt.Println("\nDoctor passed: environment looks ready")
			return nil
		},
	}
}

func watchCmd() *cobra.Command {
	var interval time.Duration

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Live terminal view of container network traffic",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWatch(cmd.Context(), interval)
		},
	}

	cmd.Flags().DurationVarP(&interval, "interval", "i", 2*time.Second, "polling interval")

	return cmd
}

func runWatch(ctx context.Context, interval time.Duration) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run with sudo")
	}

	resolver := dockerresolver.New()
	containers, err := resolver.Discover(ctx)
	if err != nil {
		return err
	}

	if len(containers) == 0 {
		return fmt.Errorf("no docker container cgroups found")
	}

	collector, err := ebpfcollector.New()
	if err != nil {
		return err
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

	ticker := time.NewTicker(interval)
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
	return nil
}

func printDoctorResult(result doctor.CheckResult) {
	status := string(result.Status)
	if result.Err != nil {
		fmt.Printf("[%s] %-14s %s: %v\n", status, result.Name, result.Details, result.Err)
		return
	}

	fmt.Printf("[%s] %-14s %s\n", status, result.Name, result.Details)
}
