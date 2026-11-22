// SPDX-License-Identifier: Apache-2.0

// gke-caa-heartbeat keeps one authorized CAA agent connection active while
// the guest waits for the signed Plan. It sends only Health.Check.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/containerd/ttrpc"
	pb "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
)

const (
	caaPods = "/run/peerpod/pods"
	bundles = "/run/containerd/io.containerd.runtime.v2.task/k8s.io"
)

var (
	heartbeatPodUID = regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
	heartbeatPod    = regexp.MustCompile(`^proof-1$`)
	heartbeatPrefix = regexp.MustCompile(`^[a-f0-9]{8}$`)
	heartbeatID     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func boundHeartbeatSocket(podRoot, bundleRoot, uid, pod, prefix string) (string, error) {
	entries, err := os.ReadDir(podRoot)
	if err != nil {
		return "", err
	}
	var socket string
	for _, entry := range entries {
		id := entry.Name()
		if !entry.IsDir() || !heartbeatID.MatchString(id) || !strings.HasPrefix(id, prefix) {
			continue
		}
		bundle, err := os.Open(filepath.Join(bundleRoot, id, "config.json"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		var config struct{ Annotations map[string]string }
		err = json.NewDecoder(io.LimitReader(bundle, 1<<20)).Decode(&config)
		bundle.Close()
		if err != nil {
			return "", err
		}
		annotations := config.Annotations
		if annotations["io.kubernetes.cri.sandbox-uid"] != uid ||
			annotations["io.kubernetes.cri.sandbox-namespace"] != "execution-proof" ||
			annotations["io.kubernetes.cri.sandbox-name"] != pod ||
			annotations["io.kubernetes.cri.container-type"] != "sandbox" {
			continue
		}
		path := filepath.Join(podRoot, id, "agent.ttrpc")
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSocket == 0 || socket != "" {
			return "", errors.New("expected one CAA socket for the bound sandbox")
		}
		socket = path
	}
	return socket, nil
}

func heartbeat(ctx context.Context, podRoot, bundleRoot, uid, pod, prefix string, output io.Writer) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var client *ttrpc.Client
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	bound, ready := false, false
	for {
		if client == nil {
			socket, err := boundHeartbeatSocket(podRoot, bundleRoot, uid, pod, prefix)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if socket != "" {
				conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(ctx, "unix", socket)
				if err == nil {
					client = ttrpc.NewClient(conn)
					if !bound {
						if _, err := fmt.Fprintln(output, "ONB17_CAA_HEARTBEAT_BOUND"); err != nil {
							return err
						}
						bound = true
					}
				}
			}
		}
		if client != nil {
			call, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
			reply, err := pb.NewHealthClient(client).Check(call, &pb.CheckRequest{})
			cancel()
			if err == nil && reply.GetStatus() == pb.HealthCheckResponse_SERVING {
				if !ready {
					if _, err := fmt.Fprintln(output, "ONB17_CAA_HEARTBEAT_READY"); err != nil {
						return err
					}
					ready = true
				}
			} else if ready && ctx.Err() == nil {
				return errors.New("CAA health check stopped responding")
			} else if !ready && err != nil {
				client.Close()
				client = nil
			}
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return ctx.Err()
			}
			if ready {
				return nil
			}
			return errors.New("CAA health check did not become ready")
		case <-ticker.C:
		}
	}
}

func main() {
	if len(os.Args) != 4 || !heartbeatPodUID.MatchString(os.Args[1]) || !heartbeatPod.MatchString(os.Args[2]) ||
		!heartbeatPrefix.MatchString(os.Args[3]) {
		fmt.Fprintln(os.Stderr, "usage: gke-caa-heartbeat POD_UID POD_NAME SANDBOX_ID_PREFIX")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 360*time.Second)
	defer cancel()
	// Closing the operator's kubectl stdin ends this attempt's helper.
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		cancel()
	}()
	if err := heartbeat(ctx, caaPods, bundles, os.Args[1], os.Args[2], os.Args[3], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "CAA heartbeat:", err)
		os.Exit(1)
	}
}
