package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	simpleaggregator "docker-net-ebpf/internal/aggregator/simple"
	ebpfcollector "docker-net-ebpf/internal/collector/ebpf"
	"docker-net-ebpf/internal/doctor"
	consoleoutput "docker-net-ebpf/internal/output/console"
	fanoutoutput "docker-net-ebpf/internal/output/fanout"
	jsonloutput "docker-net-ebpf/internal/output/jsonl"
	dockerresolver "docker-net-ebpf/internal/resolver/docker"
	sqliteoutput "docker-net-ebpf/internal/output/sqlite"
	"docker-net-ebpf/netwatch"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "docker-net-ebpf",
		Short: "Container network observability using eBPF",
	}

	root.AddCommand(doctorCmd())
	root.AddCommand(watchCmd())
	root.AddCommand(recordCmd())

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
		Use:   "watch [output [path]]...",
		Short: "Live terminal view of container network traffic",
		RunE: func(cmd *cobra.Command, args []string) error {
			output, err := buildOutputs(args, []outputSpec{{kind: "console"}})
			if err != nil {
				return err
			}
			return runCollectionLoop(cmd.Context(), interval, output)
		},
	}

	cmd.Flags().DurationVarP(&interval, "interval", "i", 2*time.Second, "polling interval")

	cmd.Example = strings.Join([]string{
		"docker-net-ebpf watch",
		"docker-net-ebpf watch console jsonl ./traffic.jsonl sqlite ./traffic.db",
		"docker-net-ebpf watch jsonl sqlite",
	}, "\n")

	return cmd
}

func recordCmd() *cobra.Command {
	var interval time.Duration

	cmd := &cobra.Command{
		Use:   "record [output [path]]...",
		Short: "Record container network traffic to durable outputs",
		RunE: func(cmd *cobra.Command, args []string) error {
			output, err := buildOutputs(args, []outputSpec{{kind: "jsonl", path: defaultPath("jsonl")}})
			if err != nil {
				return err
			}
			return runCollectionLoop(cmd.Context(), interval, output)
		},
	}

	cmd.Flags().DurationVarP(&interval, "interval", "i", 2*time.Second, "polling interval")
	cmd.Example = strings.Join([]string{
		"docker-net-ebpf record",
		"docker-net-ebpf record jsonl ./traffic.jsonl sqlite ./traffic.db",
		"docker-net-ebpf record sqlite console",
	}, "\n")

	return cmd
}

func runCollectionLoop(ctx context.Context, interval time.Duration, output netwatch.Output) error {
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
	defer output.Close()

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

type outputSpec struct {
	kind string
	path string
}

func buildOutputs(args []string, defaults []outputSpec) (netwatch.Output, error) {
	specs, err := parseOutputSpecs(args, defaults)
	if err != nil {
		return nil, err
	}

	outputs := make([]netwatch.Output, 0, len(specs))
	for _, spec := range specs {
		output, err := newOutput(spec)
		if err != nil {
			for _, created := range outputs {
				_ = created.Close()
			}
			return nil, err
		}
		outputs = append(outputs, output)
	}

	return fanoutoutput.New(outputs...), nil
}

func parseOutputSpecs(args []string, defaults []outputSpec) ([]outputSpec, error) {
	if len(args) == 0 {
		return defaults, nil
	}

	specs := make([]outputSpec, 0, len(args))
	for i := 0; i < len(args); i++ {
		kind := normalizeOutputKind(args[i])
		if kind == "" {
			return nil, fmt.Errorf("unknown output %q; valid outputs are console, jsonl, sqlite", args[i])
		}

		spec := outputSpec{kind: kind, path: defaultPath(kind)}
		if i+1 < len(args) {
			nextKind := normalizeOutputKind(args[i+1])
			if nextKind == "" {
				spec.path = args[i+1]
				i++
			}
		}

		specs = append(specs, spec)
	}

	return specs, nil
}

func newOutput(spec outputSpec) (netwatch.Output, error) {
	switch spec.kind {
	case "console":
		return consoleoutput.New(), nil
	case "jsonl":
		return jsonloutput.New(spec.path)
	case "sqlite":
		return sqliteoutput.New(spec.path)
	default:
		return nil, fmt.Errorf("unsupported output %q", spec.kind)
	}
}

func normalizeOutputKind(value string) string {
	switch strings.ToLower(value) {
	case "console", "stdout":
		return "console"
	case "jsonl", "json":
		return "jsonl"
	case "sqlite", "sqlite3", "db":
		return "sqlite"
	default:
		return ""
	}
}

func defaultPath(kind string) string {
	switch kind {
	case "jsonl":
		return filepath.Join("output", "traffic.jsonl")
	case "sqlite":
		return filepath.Join("output", "traffic.db")
	default:
		return ""
	}
}
