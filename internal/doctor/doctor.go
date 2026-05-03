package doctor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	ebpfcollector "docker-net-ebpf/internal/collector/ebpf"
	"docker-net-ebpf/netwatch"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

const (
	capSysAdmin = 21
	capPerfMon  = 38
	capBPF      = 39

	cgroup2SuperMagic = 0x63677270
	bpfFSMagic        = 0xcafe4a11
)

type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusWarn Status = "WARN"
)

type CheckResult struct {
	Name    string
	Status  Status
	Details string
	Err     error
}

func Checks(ctx context.Context) []CheckResult {
	return []CheckResult{
		checkLinuxKernel(),
		checkPrivileges(),
		checkCgroupV2(),
		checkBPFFS(),
		checkBTF(),
		checkDockerSocket(ctx),
		checkAttachAbility(ctx),
	}
}


func FailureCount(results []CheckResult) int {
	failures := 0
	for _, result := range results {
		if result.Status == StatusFail {
			failures++
		}
	}
	return failures
}

func checkLinuxKernel() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{
			Name:    "Linux kernel",
			Status:  StatusFail,
			Details: fmt.Sprintf("GOOS=%s; this tool requires a Linux kernel", runtime.GOOS),
		}
	}

	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return CheckResult{Name: "Linux kernel", Status: StatusFail, Details: "unable to read kernel version", Err: err}
	}

	return CheckResult{
		Name:    "Linux kernel",
		Status:  StatusPass,
		Details: fmt.Sprintf("kernel=%s arch=%s", utsnameToString(uname.Release[:]), utsnameToString(uname.Machine[:])),
	}
}

func checkPrivileges() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{Name: "root/CAP_BPF", Status: StatusFail, Details: "non-Linux environment"}
	}

	euid := os.Geteuid()
	capEff, err := effectiveCapabilities()
	if err != nil {
		return CheckResult{Name: "root/CAP_BPF", Status: StatusFail, Details: "unable to read effective capabilities", Err: err}
	}

	parts := []string{fmt.Sprintf("euid=%d", euid), fmt.Sprintf("CapEff=%#x", capEff)}
	if euid == 0 {
		parts = append(parts, "running as root")
		return CheckResult{Name: "root/CAP_BPF", Status: StatusPass, Details: strings.Join(parts, "; ")}
	}

	hasBPF := capabilitySet(capEff, capBPF)
	hasPerfMon := capabilitySet(capEff, capPerfMon)
	hasSysAdmin := capabilitySet(capEff, capSysAdmin)
	parts = append(parts, fmt.Sprintf("CAP_BPF=%t", hasBPF), fmt.Sprintf("CAP_PERFMON=%t", hasPerfMon), fmt.Sprintf("CAP_SYS_ADMIN=%t", hasSysAdmin))

	if hasBPF && (hasPerfMon || hasSysAdmin) {
		return CheckResult{Name: "root/CAP_BPF", Status: StatusPass, Details: strings.Join(parts, "; ")}
	}

	return CheckResult{
		Name:    "root/CAP_BPF",
		Status:  StatusFail,
		Details: fmt.Sprintf("%s; need root or BPF-related capabilities", strings.Join(parts, "; ")),
	}
}

func checkCgroupV2() CheckResult {
	var stat unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &stat); err != nil {
		return CheckResult{Name: "cgroup v2", Status: StatusFail, Details: "unable to stat /sys/fs/cgroup", Err: err}
	}

	if uint64(stat.Type) != cgroup2SuperMagic {
		return CheckResult{Name: "cgroup v2", Status: StatusFail, Details: fmt.Sprintf("found fs magic %#x at /sys/fs/cgroup", uint64(stat.Type))}
	}

	return CheckResult{Name: "cgroup v2", Status: StatusPass, Details: "/sys/fs/cgroup is cgroup2"}
}

func checkBPFFS() CheckResult {
	var stat unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &stat); err != nil {
		return CheckResult{Name: "bpffs", Status: StatusFail, Details: "unable to stat /sys/fs/bpf", Err: err}
	}

	if uint64(stat.Type) != bpfFSMagic {
		return CheckResult{Name: "bpffs", Status: StatusFail, Details: fmt.Sprintf("found fs magic %#x at /sys/fs/bpf", uint64(stat.Type))}
	}

	return CheckResult{Name: "bpffs", Status: StatusPass, Details: "/sys/fs/bpf is mounted"}
}

func checkBTF() CheckResult {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return CheckResult{Name: "BTF", Status: StatusFail, Details: "missing /sys/kernel/btf/vmlinux", Err: err}
	}

	return CheckResult{Name: "BTF", Status: StatusPass, Details: "/sys/kernel/btf/vmlinux is present"}
}

func checkDockerSocket(ctx context.Context) CheckResult {
	if info, err := os.Stat("/var/run/docker.sock"); err != nil {
		return CheckResult{Name: "Docker socket", Status: StatusFail, Details: "missing /var/run/docker.sock", Err: err}
	} else if info.Mode()&os.ModeSocket == 0 {
		return CheckResult{Name: "Docker socket", Status: StatusFail, Details: "/var/run/docker.sock exists but is not a socket"}
	}

	cli, err := client.NewClientWithOpts(
		client.WithHost("unix:///var/run/docker.sock"),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return CheckResult{Name: "Docker socket", Status: StatusFail, Details: "unable to create Docker API client", Err: err}
	}
	defer cli.Close()

	ping, err := cli.Ping(ctx, client.PingOptions{})
	if err != nil {
		return CheckResult{Name: "Docker socket", Status: StatusFail, Details: "unable to talk to Docker Engine API", Err: err}
	}

	return CheckResult{Name: "Docker socket", Status: StatusPass, Details: fmt.Sprintf("Docker API reachable (api=%s)", ping.APIVersion)}
}

func checkAttachAbility(ctx context.Context) CheckResult {
	path, err := selfCgroupPath()
	if err != nil {
		return CheckResult{Name: "eBPF attach", Status: StatusFail, Details: "unable to locate current cgroup", Err: err}
	}

	id, err := cgroupID(path)
	if err != nil {
		return CheckResult{Name: "eBPF attach", Status: StatusFail, Details: "unable to stat current cgroup", Err: err}
	}

	collector, err := ebpfcollector.New()
	if err != nil {
		return CheckResult{Name: "eBPF attach", Status: StatusFail, Details: "unable to load eBPF objects", Err: err}
	}
	defer collector.Close()

	container := netwatch.ContainerInfo{
		ID:         "self",
		Name:       "self",
		CgroupID:   id,
		CgroupPath: path,
		Runtime:    "self",
	}

	if err := collector.Attach(ctx, container); err != nil {
		return CheckResult{Name: "eBPF attach", Status: StatusFail, Details: fmt.Sprintf("attach to %s failed", path), Err: err}
	}

	if err := collector.Detach(ctx, container); err != nil {
		return CheckResult{Name: "eBPF attach", Status: StatusWarn, Details: fmt.Sprintf("attach succeeded but detach failed for %s", path), Err: err}
	}

	return CheckResult{Name: "eBPF attach", Status: StatusPass, Details: fmt.Sprintf("attached successfully to %s", path)}
}

func selfCgroupPath() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[1] != "" {
			continue
		}
		path := filepath.Clean(filepath.Join("/sys/fs/cgroup", parts[2]))
		return path, nil
	}

	return "", fmt.Errorf("no cgroup v2 entry found in /proc/self/cgroup")
}

func cgroupID(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}

	return st.Ino, nil
}

func effectiveCapabilities() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}

		raw := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		return strconv.ParseUint(raw, 16, 64)
	}

	return 0, fmt.Errorf("CapEff not found in /proc/self/status")
}

func capabilitySet(caps uint64, bit uint) bool {
	return caps&(uint64(1)<<bit) != 0
}

func utsnameToString(field interface{}) string {
	switch v := field.(type) {
	case []byte:
		end := 0
		for end < len(v) && v[end] != 0 {
			end++
		}
		return string(v[:end])
	case []int8:
		buf := make([]byte, 0, len(v))
		for _, c := range v {
			if c == 0 {
				break
			}
			buf = append(buf, byte(c))
		}
		return string(buf)
	default:
		return ""
	}
}
