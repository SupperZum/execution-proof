// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/ttrpc"
	pb "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
)

type testHealth struct {
	pb.HealthService
	calls atomic.Int32
	tick  chan struct{}
	stop  chan struct{}
}

func (h *testHealth) Check(ctx context.Context, _ *pb.CheckRequest) (*pb.HealthCheckResponse, error) {
	if h.calls.Add(1) == 1 {
		return &pb.HealthCheckResponse{Status: pb.HealthCheckResponse_SERVING}, nil
	}
	close(h.tick)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-h.stop:
		return &pb.HealthCheckResponse{Status: pb.HealthCheckResponse_NOT_SERVING}, nil
	}
}

func TestHeartbeatRedialAndShutdown(t *testing.T) {
	for _, tc := range []string{"cancel-during-tick", "lost-health"} {
		t.Run(tc, func(t *testing.T) {
			// The bound sandbox ID occupies 64 bytes of a Unix socket pathname.
			root, err := os.MkdirTemp("/tmp", "hb-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			id := strings.Repeat("ab", 32)
			pods, tasks := filepath.Join(root, "p"), filepath.Join(root, "t")
			for _, dir := range []string{pods, tasks} {
				if err := os.MkdirAll(filepath.Join(dir, id), 0700); err != nil {
					t.Fatal(err)
				}
			}
			const uid = "0027be54-893f-410b-9d7a-b130575f7320"
			config := `{"annotations":{"io.kubernetes.cri.sandbox-uid":"` + uid + `","io.kubernetes.cri.sandbox-name":"proof-2","io.kubernetes.cri.sandbox-namespace":"execution-proof","io.kubernetes.cri.container-type":"sandbox"}}`
			if err := os.WriteFile(filepath.Join(tasks, id, "config.json"), []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("unix", filepath.Join(pods, id, "agent.ttrpc"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server, err := ttrpc.NewServer()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			service := &testHealth{tick: make(chan struct{}), stop: make(chan struct{})}
			pb.RegisterHealthService(server, service)
			go func() {
				// Drop the first accepted connection before answering Health.Check.
				first, err := listener.Accept()
				if err != nil {
					return
				}
				first.Close()
				_ = server.Serve(ctx, listener)
			}()
			var markers bytes.Buffer
			done := make(chan error, 1)
			go func() { done <- heartbeat(ctx, pods, tasks, uid, "proof-2", id[:8], &markers) }()
			select {
			case <-service.tick:
			case <-ctx.Done():
				t.Fatal("no heartbeat tick after redial")
			}
			if tc == "cancel-during-tick" {
				cancel()
			} else {
				close(service.stop)
			}
			select {
			case err := <-done:
				if tc == "cancel-during-tick" && err != nil {
					t.Fatal(err)
				}
				if tc == "lost-health" && (err == nil || err.Error() != "CAA health check stopped responding") {
					t.Fatalf("health loss: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("heartbeat did not finish")
			}
			if got := markers.String(); got != "ONB17_CAA_HEARTBEAT_BOUND\nONB17_CAA_HEARTBEAT_READY\n" {
				t.Fatalf("markers: %q", got)
			}
		})
	}
}

func TestHeartbeatPodName(t *testing.T) {
	for _, name := range []string{"proof-1", "proof-2", strings.Repeat("x", 63)} {
		if !heartbeatPod.MatchString(name) {
			t.Errorf("rejected Pod name %q", name)
		}
	}
	for _, name := range []string{"", "../proof-2", "-bad", "bad-", strings.Repeat("x", 64)} {
		if heartbeatPod.MatchString(name) {
			t.Errorf("accepted invalid Pod name %q", name)
		}
	}
}
