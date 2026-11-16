// SPDX-License-Identifier: Apache-2.0

// qualification_kata drives one direct qualification attempt through the
// operator's Unix proxy or pinned TLS relay to the measured sandbox gateway.
package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/containerd/ttrpc"
	pb "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const (
	qualificationRole = "io.kubernetes.cri.container-type"
	// The measured qualification relay has an idle timeout of one second.
	qualificationHeartbeatPeriod  = 200 * time.Millisecond
	qualificationHeartbeatTimeout = 700 * time.Millisecond
)

var (
	qualificationID    = regexp.MustCompile(`^qexp-[a-z0-9]([a-z0-9-]{0,94}[a-z0-9])?$`)
	qualificationImage = regexp.MustCompile(`^[A-Za-z0-9.:-][A-Za-z0-9_.:-]*/[A-Za-z0-9_./-]+@sha256:[a-f0-9]{64}$`)
	qualificationPin   = regexp.MustCompile(`^[a-f0-9]{96}$`)
)

func qualificationSHA384(data []byte) string {
	digest := sha512.Sum384(data)
	return hex.EncodeToString(digest[:])
}

type createWrite struct {
	frameBytes int
	commitment string
}

type qualificationConn struct {
	net.Conn
	deadline time.Time
	pending  atomic.Pointer[createWrite]
	sent     chan string
}

func (c *qualificationConn) Write(data []byte) (int, error) {
	// ttrpc performs the connection write before observing the call context.
	writeDeadline := time.Now().Add(qualificationHeartbeatTimeout)
	if c.deadline.Before(writeDeadline) {
		writeDeadline = c.deadline
	}
	if err := c.Conn.SetWriteDeadline(writeDeadline); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(data)
	if pending := c.pending.Swap(nil); pending != nil && err == nil && n == pending.frameBytes {
		c.sent <- pending.commitment
	}
	return n, err
}

func openQualificationProxy(ctx context.Context, path string) (*net.UnixConn, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid Unix proxy path")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("expected an owned Unix proxy socket")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, errors.New("Unix proxy connection failed")
	}
	conn := connection.(*net.UnixConn)
	raw, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, errors.New("Unix proxy credentials unavailable")
	}
	var peer *unix.Ucred
	if err := raw.Control(func(fd uintptr) {
		peer, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || peer == nil || peer.Uid != uint32(os.Geteuid()) {
		conn.Close()
		return nil, errors.New("unexpected Unix proxy owner")
	}
	return conn, nil
}

type qualificationRelayConfig struct {
	Endpoint         string `json:"endpoint"`
	ServerCAPath     string `json:"server_ca_path"`
	ServerCASHA384   string `json:"server_ca_sha384"`
	ServerLeafSHA384 string `json:"server_leaf_der_sha384"`
	ClientCertPath   string `json:"client_cert_path"`
	ClientCertSHA384 string `json:"client_cert_sha384"`
	ClientKeyPath    string `json:"client_key_path"`
}

func decodeQualificationRelay(data []byte) (qualificationRelayConfig, error) {
	var config qualificationRelayConfig
	rejected := errors.New("invalid TLS relay configuration")
	remaining := map[string]*string{
		"endpoint": &config.Endpoint, "server_ca_path": &config.ServerCAPath,
		"server_ca_sha384": &config.ServerCASHA384, "server_leaf_der_sha384": &config.ServerLeafSHA384,
		"client_cert_path": &config.ClientCertPath, "client_cert_sha384": &config.ClientCertSHA384,
		"client_key_path": &config.ClientKeyPath,
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return config, rejected
	}
	for decoder.More() {
		token, err := decoder.Token()
		name, _ := token.(string)
		field := remaining[name]
		if err != nil || field == nil || decoder.Decode(field) != nil || *field == "" {
			return config, rejected
		}
		delete(remaining, name)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(remaining) != 0 {
		return config, rejected
	}
	if _, err := decoder.Token(); err != io.EOF {
		return config, rejected
	}
	host, port, err := net.SplitHostPort(config.Endpoint)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n\x00/") ||
		portErr != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port ||
		!qualificationPin.MatchString(config.ServerCASHA384) || !qualificationPin.MatchString(config.ServerLeafSHA384) ||
		!qualificationPin.MatchString(config.ClientCertSHA384) {
		return config, rejected
	}
	return config, nil
}

func readQualificationFile(path string, limit int64, private bool) ([]byte, error) {
	rejected := errors.New("TLS relay file rejected")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, rejected
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, rejected
	}
	file := os.NewFile(uintptr(fd), "qualification-relay-input")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return nil, rejected
	}
	stat := info.Sys().(*syscall.Stat_t)
	if private && (stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1) {
		return nil, rejected
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != info.Size() {
		if private {
			clear(data)
		}
		return nil, rejected
	}
	return data, nil
}

func loadQualificationRelay(path string) (string, *tls.Config, error) {
	data, err := readQualificationFile(path, 16<<10, false)
	if err != nil {
		return "", nil, err
	}
	config, err := decodeQualificationRelay(data)
	if err != nil {
		return "", nil, err
	}
	ca, err := readQualificationFile(config.ServerCAPath, 64<<10, false)
	roots := x509.NewCertPool()
	if err != nil || qualificationSHA384(ca) != config.ServerCASHA384 || !roots.AppendCertsFromPEM(ca) {
		return "", nil, errors.New("TLS relay CA rejected")
	}
	cert, err := readQualificationFile(config.ClientCertPath, 64<<10, false)
	if err != nil || qualificationSHA384(cert) != config.ClientCertSHA384 {
		return "", nil, errors.New("TLS relay client certificate rejected")
	}
	key, err := readQualificationFile(config.ClientKeyPath, 16<<10, true)
	if err != nil {
		return "", nil, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	clear(key)
	if err != nil {
		return "", nil, errors.New("TLS relay client key pair rejected")
	}
	return config.Endpoint, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: "podvm-server", RootCAs: roots, Certificates: []tls.Certificate{pair},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 ||
				qualificationSHA384(state.PeerCertificates[0].Raw) != config.ServerLeafSHA384 {
				return errors.New("TLS relay server identity rejected")
			}
			return nil
		},
	}, nil
}

func openQualificationRelay(ctx context.Context, path string) (net.Conn, error) {
	endpoint, config, err := loadQualificationRelay(path)
	if err != nil {
		return nil, err
	}
	dialer := tls.Dialer{Config: config}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, errors.New("TLS relay connection failed")
	}
	return conn, nil
}

func qualificationRoot(cid string) string {
	return "/run/kata-containers/" + cid + "/rootfs"
}

func qualificationPause(cid string) *pb.CreateContainerRequest {
	return &pb.CreateContainerRequest{
		ContainerId: cid,
		ExecId:      cid,
		Storages: []*pb.Storage{{
			Driver: "image_guest_pull", Source: "pause", Fstype: "overlay", MountPoint: qualificationRoot(cid),
		}},
		OCI: &pb.Spec{Annotations: map[string]string{qualificationRole: "sandbox"}},
	}
}

func qualificationApp(cid, image string) *pb.CreateContainerRequest {
	// This is the gateway's minimal Kata guest-pull wire shape. The protected
	// process and rootfs are reconstructed in the guest from the signed plan.
	metadata := `image_guest_pull={"metadata":{"io.katacontainers.pkg.oci.container_type":"pod_container","io.kubernetes.cri.image-name":"` + image + `"}}`
	root := qualificationRoot(cid)
	return &pb.CreateContainerRequest{
		ContainerId: cid,
		ExecId:      cid,
		Storages: []*pb.Storage{{
			Driver: "image_guest_pull", DriverOptions: []string{metadata}, Source: image, Fstype: "overlay", MountPoint: root,
		}},
		OCI: &pb.Spec{
			Process: &pb.Process{
				User: &pb.User{UID: 1000, GID: 1000}, Args: []string{"/app"}, Env: []string{"HOME=/"}, Cwd: "/", NoNewPrivileges: true,
			},
			Root:        &pb.Root{Path: root, Readonly: true},
			Annotations: map[string]string{qualificationRole: "container"},
			Linux: &pb.Linux{
				Resources:  &pb.LinuxResources{},
				Namespaces: []*pb.LinuxNamespace{{Type: "mount"}, {Type: "ipc"}, {Type: "uts"}},
			},
		},
	}
}

func keepQualificationRelayAlive(ctx context.Context, abort context.CancelFunc, health pb.HealthService) func() {
	keepalive, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticks := time.NewTicker(qualificationHeartbeatPeriod)
		defer ticks.Stop()
		for {
			select {
			case <-keepalive.Done():
				return
			case <-ticks.C:
				call, cancel := context.WithTimeout(keepalive, qualificationHeartbeatTimeout)
				response, err := health.Check(call, &pb.CheckRequest{})
				cancel()
				if err != nil || response.GetStatus() != pb.HealthCheckResponse_SERVING {
					if keepalive.Err() == nil {
						abort()
					}
					return
				}
			}
		}
	}()
	return func() {
		stop()
		<-done
	}
}

func runQualificationKata(ctx context.Context, conn net.Conn, cid, sandbox, image string, input io.Reader, output io.Writer) error {
	deadline, bounded := ctx.Deadline()
	if !bounded || conn.SetDeadline(deadline) != nil {
		return errors.New("transport deadline setup failed")
	}
	ctx, abort := context.WithCancel(ctx)
	defer abort()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	wire := &qualificationConn{Conn: conn, deadline: deadline, sent: make(chan string, 1)}
	appCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := ttrpc.NewClient(wire, ttrpc.WithUnaryClientInterceptor(func(callCtx context.Context, req *ttrpc.Request,
		resp *ttrpc.Response, _ *ttrpc.UnaryClientInfo, invoke ttrpc.Invoker) error {
		if callCtx == appCtx {
			// The interceptor receives the already-marshaled payload used by
			// dispatch. ttrpc v1.2.7 buffers this bounded request and flushes
			// its 10-byte header and entire body in one connection write.
			frameBytes := 10 + proto.Size(req)
			if frameBytes > 4096 {
				return errors.New("app Create frame exceeds write bound")
			}
			wire.pending.Store(&createWrite{frameBytes, qualificationSHA384(req.Payload)})
		}
		return invoke(callCtx, req, resp)
	}))
	defer client.Close()
	agent := pb.NewAgentServiceClient(client)
	if _, err := agent.CreateSandbox(ctx, &pb.CreateSandboxRequest{SandboxId: sandbox}); err != nil {
		return errors.New("CreateSandbox failed")
	}
	if _, err := agent.CreateContainer(ctx, qualificationPause(sandbox)); err != nil {
		return errors.New("pause CreateContainer failed")
	}
	if _, err := agent.StartContainer(ctx, &pb.StartContainerRequest{ContainerId: sandbox}); err != nil {
		return errors.New("pause StartContainer failed")
	}
	created := make(chan error, 1)
	go func() {
		_, err := agent.CreateContainer(appCtx, qualificationApp(cid, image))
		created <- err
	}()
	events := json.NewEncoder(output)
	var commitment string
	select {
	case commitment = <-wire.sent:
	case result := <-created:
		// If the reply was immediate, the full write still precedes it.
		select {
		case commitment = <-wire.sent:
			created <- result
		default:
			return errors.New("app CreateContainer ended before pending notification")
		}
	case <-ctx.Done():
		return errors.New("app CreateContainer write deadline")
	}
	if err := events.Encode(map[string]any{"phase": "pending", "container_id": cid, "wire_sha384": commitment}); err != nil {
		return errors.New("pending event write failed")
	}
	stopKeepalive := keepQualificationRelayAlive(ctx, abort, pb.NewHealthClient(client))
	defer stopKeepalive()
	start := make(chan bool, 1)
	go func() {
		var command [len("START\n")]byte
		_, err := io.ReadFull(input, command[:])
		start <- err == nil && string(command[:]) == "START\n"
	}()
	select {
	case ok := <-start:
		if !ok {
			return errors.New("START command rejected")
		}
	case <-ctx.Done():
		return errors.New("START command deadline")
	}
	if err := <-created; err != nil {
		return errors.New("app CreateContainer failed")
	}
	if _, err := agent.StartContainer(ctx, &pb.StartContainerRequest{ContainerId: cid}); err != nil {
		return errors.New("app StartContainer failed")
	}
	if err := events.Encode(map[string]any{"phase": "started"}); err != nil {
		return errors.New("started event write failed")
	}
	wait, err := agent.WaitProcess(ctx, &pb.WaitProcessRequest{ContainerId: cid, ExecId: cid})
	stopKeepalive()
	if err != nil || ctx.Err() != nil {
		return errors.New("app WaitProcess failed")
	}
	_, removeErr := agent.RemoveContainer(ctx, &pb.RemoveContainerRequest{ContainerId: cid, Timeout: 5})
	_, destroyErr := agent.DestroySandbox(ctx, &pb.DestroySandboxRequest{})
	if removeErr != nil || destroyErr != nil {
		return errors.New("sandbox teardown failed")
	}
	if wait.Status != 0 {
		return errors.New("app exited nonzero")
	}
	if err := events.Encode(map[string]any{"phase": "finished", "wait_status": wait.Status}); err != nil {
		return errors.New("finished event write failed")
	}
	return nil
}

func qualificationMain(args []string) error {
	flags := flag.NewFlagSet("qualification-kata", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socket := flags.String("socket", "", "owned, authenticated Unix proxy socket")
	relay := flags.String("relay-config", "", "pinned TLS relay configuration")
	cid := flags.String("cid", "", "qualification app ID")
	sandbox := flags.String("sandbox", "", "qualification sandbox ID")
	image := flags.String("image", "", "digest-pinned image reference")
	seconds := flags.Int("timeout-seconds", 120, "total deadline in seconds")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !qualificationID.MatchString(*cid) ||
		!qualificationID.MatchString(*sandbox) || *cid == *sandbox || len(*image) > 512 ||
		!qualificationImage.MatchString(*image) || *seconds < 1 || *seconds > 600 || (*socket == "") == (*relay == "") {
		return errors.New("invalid arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*seconds)*time.Second)
	defer cancel()
	var conn net.Conn
	var err error
	if *socket != "" {
		conn, err = openQualificationProxy(ctx, *socket)
	} else {
		conn, err = openQualificationRelay(ctx, *relay)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	return runQualificationKata(ctx, conn, *cid, *sandbox, *image, os.Stdin, os.Stdout)
}

func main() {
	if err := qualificationMain(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "qualification Kata:", err)
		os.Exit(1)
	}
}
