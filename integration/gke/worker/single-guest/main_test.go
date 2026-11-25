package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/containerd/ttrpc"
	pb "github.com/kata-containers/kata-containers/src/runtime/protocols/hypervisor"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockCAA struct {
	pb.HypervisorService
	starts atomic.Int64
}

func (*mockCAA) CreateVM(context.Context, *pb.CreateVMRequest) (*pb.CreateVMResponse, error) {
	return &pb.CreateVMResponse{}, nil
}
func (m *mockCAA) StartVM(context.Context, *pb.StartVMRequest) (*pb.StartVMResponse, error) {
	m.starts.Add(1)
	return nil, errors.New("response lost")
}
func (*mockCAA) StopVM(context.Context, *pb.StopVMRequest) (*pb.StopVMResponse, error) {
	return &pb.StopVMResponse{}, nil
}
func TestOneStartAcrossTimeoutStopReplacementAndRestart(t *testing.T) {
	ctx := context.Background()
	caa := new(mockCAA)
	g := guard{caa, t.TempDir(), t.TempDir()}
	uid := "da918b06-4070-4fd4-bd15-4d57062d7b00"
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	bundle := func(ch, owner string) *pb.CreateVMRequest {
		id := strings.Repeat(ch, 64)
		d := filepath.Join(g.bundles, id)
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
		a := map[string]string{"io.kubernetes.cri.container-type": "sandbox", "io.kubernetes.cri.sandbox-name": "proof", "io.kubernetes.cri.sandbox-namespace": "execution-proof", "io.kubernetes.cri.sandbox-uid": owner}
		b, _ := json.Marshal(map[string]any{"annotations": a})
		write(filepath.Join(d, "config.json"), b)
		return &pb.CreateVMRequest{Id: id, Annotations: a}
	}
	first := bundle("a", uid)
	other := bundle("b", uid)
	foreign := bundle("c", "unexpected")
	if _, err := g.CreateVM(ctx, first); err == nil {
		t.Fatal("unarmed")
	}
	write(filepath.Join(g.state, "pod-uid"), []byte(uid))
	if _, err := g.CreateVM(ctx, foreign); err == nil {
		t.Fatal("foreign Pod")
	}
	if _, err := g.CreateVM(ctx, first); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); g.StartVM(ctx, &pb.StartVMRequest{Id: first.Id}) }()
	}
	wg.Wait()
	if _, err := g.StopVM(ctx, &pb.StopVMRequest{Id: first.Id}); err != nil {
		t.Fatal(err)
	}
	fresh := guard{caa, g.state, g.bundles}
	if _, err := fresh.CreateVM(ctx, other); err == nil {
		t.Fatal("replacement sandbox")
	}
	for _, id := range []string{first.Id, other.Id} {
		if _, err := fresh.StartVM(ctx, &pb.StartVMRequest{Id: id}); err == nil {
			t.Fatal("repeat start")
		}
	}
	if caa.starts.Load() != 1 {
		t.Fatalf("forwarded starts = %d", caa.starts.Load())
	}
}

func TestKataRPCRefusesUnarmedGuestAndUnknownStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ttrpc.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	caa := new(mockCAA)
	pb.RegisterHypervisorService(server, &guard{caa, t.TempDir(), t.TempDir()})
	go server.Serve(context.Background(), listener)
	defer server.Close()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	client := ttrpc.NewClient(conn)
	defer client.Close()
	hypervisor := pb.NewHypervisorClient(client)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	id := strings.Repeat("a", 64)
	if _, err = hypervisor.CreateVM(ctx, &pb.CreateVMRequest{Id: id}); err == nil {
		t.Fatal("unarmed CreateVM was accepted")
	}
	if _, err = hypervisor.StartVM(ctx, &pb.StartVMRequest{Id: id}); err == nil {
		t.Fatal("unknown StartVM was accepted")
	}
	if caa.starts.Load() != 0 {
		t.Fatal("backend called")
	}
}
