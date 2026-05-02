package dockerresolver

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"docker-net-ebpf/netwatch"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

type Resolver struct {
	containers map[uint64]netwatch.ContainerInfo
	client     *client.Client
}

func New() *Resolver {
	return &Resolver{}
}

func (r *Resolver) Discover(ctx context.Context) ([]netwatch.ContainerInfo, error) {
	dockerClient, err := r.dockerClient()
	if err != nil {
		return nil, err
	}

	inspected, err := dockerClient.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil, err
	}

	r.containers = make(map[uint64]netwatch.ContainerInfo)
	containers := make([]netwatch.ContainerInfo, 0, len(inspected.Items))

	for _, inspectedContainer := range inspected.Items {
		name := primaryContainerName(inspectedContainer)
		if name == "" {
			continue
		}

		id := inspectedContainer.ID
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

func (r *Resolver) dockerClient() (*client.Client, error) {
	if r.client != nil {
		return r.client, nil
	}

	client, err := client.New(
		client.WithHost("unix:///var/run/docker.sock"),
	)
	if err != nil {
		return nil, err
	}

	r.client = client
	return r.client, nil
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

func primaryContainerName(container container.Summary) string {
	if len(container.Names) == 0 {
		return ""
	}

	return strings.TrimPrefix(container.Names[0], "/")
}
