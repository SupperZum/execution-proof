// SPDX-License-Identifier: Apache-2.0
// A single-guest Kata remote endpoint for a dedicated GKE proof worker.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/ttrpc"
	pb "github.com/kata-containers/kata-containers/src/runtime/protocols/hypervisor"
)

const stateDir = "/var/lib/onb17-single-guest"
const guardedSocket = "/run/execution-proof/single-guest.sock"
const backendSocket = "/run/peerpod/hypervisor.sock"
const bundleDir = "/run/containerd/io.containerd.runtime.v2.task/k8s.io"

var sandboxID = regexp.MustCompile("^[a-f0-9]{64}$")
var podUID = regexp.MustCompile("^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$")
var podName = regexp.MustCompile("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")

type guard struct {
	pb.HypervisorService
	state, bundles string
}

// The operator provisions a private directory and its pod-uid file once.
// Never create or reset them on daemon startup.
func (g *guard) uid() (string, error) {
	data, err := os.ReadFile(filepath.Join(g.state, "pod-uid"))
	if err != nil {
		return "", err
	}
	uid := strings.TrimSuffix(string(data), "\n")
	if !podUID.MatchString(uid) {
		return "", errors.New("invalid Pod UID")
	}
	return uid, nil
}

func (g *guard) reserve(stage, id string) error {
	file, err := os.OpenFile(filepath.Join(g.state, stage), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	// Even an interrupted write consumes the grant. Persist the directory
	// entry before the first call whose result could be lost.
	defer file.Close()
	if _, err = file.WriteString(id); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	dir, err := os.Open(g.state)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (g *guard) owns(id string) error {
	data, err := os.ReadFile(filepath.Join(g.state, "created"))
	if err != nil {
		return err
	}
	if !sandboxID.MatchString(id) || string(data) != id {
		return errors.New("sandbox differs from reserved sandbox")
	}
	return nil
}

func (g *guard) CreateVM(ctx context.Context, req *pb.CreateVMRequest) (*pb.CreateVMResponse, error) {
	if !sandboxID.MatchString(req.Id) {
		return nil, errors.New("invalid sandbox ID")
	}
	uid, err := g.uid()
	if err != nil {
		return nil, err
	}
	// Kata's remote RPC omits the Pod UID. Read the original CRI bundle.
	raw, err := os.Open(filepath.Join(g.bundles, req.Id, "config.json"))
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	var bundle struct{ Annotations map[string]string }
	if err = json.NewDecoder(io.LimitReader(raw, 1<<20)).Decode(&bundle); err != nil {
		return nil, err
	}
	a := bundle.Annotations
	const ns = "io.kubernetes.cri.sandbox-namespace"
	const name = "io.kubernetes.cri.sandbox-name"
	if a["io.kubernetes.cri.container-type"] != "sandbox" || a["io.kubernetes.cri.sandbox-uid"] != uid ||
		a[ns] != "execution-proof" || a[ns] != req.Annotations[ns] || !podName.MatchString(a[name]) || a[name] != req.Annotations[name] {
		return nil, errors.New("sandbox does not match armed proof Pod")
	}
	if err = g.reserve("created", req.Id); err != nil {
		return nil, err
	}
	return g.HypervisorService.CreateVM(ctx, req)
}

func (g *guard) StartVM(ctx context.Context, req *pb.StartVMRequest) (*pb.StartVMResponse, error) {
	if err := g.owns(req.Id); err != nil {
		return nil, err
	}
	if err := g.reserve("started", req.Id); err != nil {
		return nil, err
	}
	return g.HypervisorService.StartVM(ctx, req)
}

func (g *guard) StopVM(ctx context.Context, req *pb.StopVMRequest) (*pb.StopVMResponse, error) {
	if err := g.owns(req.Id); err != nil {
		return nil, err
	}
	return g.HypervisorService.StopVM(ctx, req)
}

func checkState() error {
	info, err := os.Lstat(stateDir)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return errors.New("requires root-owned private state")
	}
	return nil
}

func ready(uid string) error {
	if !podUID.MatchString(uid) {
		return errors.New("invalid Pod UID")
	}
	g := guard{state: stateDir}
	for _, name := range []string{"created", "started"} {
		if _, err := os.Lstat(filepath.Join(stateDir, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("single guest grant unavailable")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "/run/execution-proof/check-runtime.sh", "--single-guest").Run(); err != nil {
		return err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", guardedSocket)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := ttrpc.NewClient(conn)
	defer client.Close()
	v, err := pb.NewHypervisorClient(client).Version(ctx, &pb.VersionRequest{})
	if err != nil {
		return err
	}
	if v.Version == "" {
		return errors.New("missing CAA version")
	}
	if err = g.reserve("pod-uid", uid); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	bound, err := g.uid()
	if err != nil {
		return err
	}
	if bound != uid {
		return errors.New("worker already assigned")
	}
	return nil
}

func serve() error {
	conn, err := net.Dial("unix", backendSocket)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := ttrpc.NewClient(conn)
	defer client.Close()
	server, err := ttrpc.NewServer()
	if err != nil {
		return err
	}
	defer server.Close()
	pb.RegisterHypervisorService(server, &guard{pb.NewHypervisorClient(client), stateDir, bundleDir})
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return errors.New("requires the dedicated systemd socket")
	}
	file := os.NewFile(3, "single-guest.socket")
	if file == nil {
		return errors.New("missing socket descriptor")
	}
	listener, err := net.FileListener(file)
	file.Close()
	if err != nil {
		return err
	}
	defer listener.Close()
	if listener.Addr().Network() != "unix" || listener.Addr().String() != guardedSocket {
		return errors.New("unexpected worker socket")
	}
	return server.Serve(context.Background(), listener)
}
func main() {
	syscall.Umask(0077)
	err := checkState()
	if err == nil {
		switch {
		case len(os.Args) == 1:
			err = serve()
		case len(os.Args) == 3 && os.Args[1] == "ready":
			err = ready(os.Args[2])
		default:
			err = errors.New("expected no arguments, or ready POD_UID")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
