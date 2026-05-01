package dockerresolver

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"docker-net-ebpf/netwatch"
	"golang.org/x/sys/unix"
)

type Resolver struct {
	containers map[uint64]netwatch.ContainerInfo
}

func New() *Resolver {
	return &Resolver{}
}

func (r *Resolver) Discover(_ context.Context) ([]netwatch.ContainerInfo, error) {
	out, err := exec.Command("docker", "ps", "--format", "{{.ID}} {{.Names}}",).Output()
	if err != nil {
		return nil, err
	}

	r.containers = make(map[uint64]netwatch.ContainerInfo)
	containers := make([]netwatch.ContainerInfo, 0)
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

		container := netwatch.ContainerInfo{
			ID:         id,
			Name:       name,
			CgroupID:   cgroupID,
			CgroupPath: path,
			Runtime:    "docker",
		}

		r.containers[cgroupID] = container
		containers = append(containers, container)
	}

	return containers, nil
}

func (r *Resolver) Resolve(_ context.Context, cgroupID uint64) (netwatch.ContainerInfo, error) {
	container, ok := r.containers[cgroupID]
	if !ok {
		return netwatch.ContainerInfo{}, fmt.Errorf("container for cgroup %d not found", cgroupID)
	}

	return container, nil
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
