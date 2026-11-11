package managementrelay

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func readinessAlias(t *testing.T, fd int) int {
	t.Helper()
	alias, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, 128)
	if errno != 0 {
		t.Fatal(errno)
	}
	return int(alias)
}

func readinessPipe(t *testing.T) (*os.File, *StartupReadiness) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	alias := readinessAlias(t, int(writer.Fd()))
	writer.Close()
	ready, err := LoadStartupReadiness(strconv.Itoa(alias))
	if err != nil {
		reader.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close(); ready.Close() })
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return reader, ready
}

func TestStartupReadinessRequiresOnePrivateWriteOnlyPipe(t *testing.T) {
	for _, hint := range []string{"", "3", "127", "4096", "0128", "+128", " 128", "128\n", "128:129", strings.Repeat("1", 10000)} {
		if _, err := ParseReadyFDHint(hint); err != ErrConfiguration {
			t.Fatal("invalid readiness alias accepted")
		}
	}
	for _, hint := range []string{"128", "4095"} {
		if _, err := ParseReadyFDHint(hint); err != nil {
			t.Fatal("valid readiness alias rejected")
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	alias := readinessAlias(t, int(reader.Fd()))
	if _, err := LoadStartupReadiness(strconv.Itoa(alias)); err != ErrConfiguration {
		t.Fatal("read-only pipe accepted as readiness output")
	}
	file := os.NewFile(uintptr(memfd(t, []byte("not-a-ready-pipe"), 15)), "test-regular")
	defer file.Close()
	alias = readinessAlias(t, int(file.Fd()))
	if _, err := LoadStartupReadiness(strconv.Itoa(alias)); err != ErrConfiguration {
		t.Fatal("regular file accepted as readiness output")
	}
	input, ready := readinessPipe(t)
	if err := ready.signal(); err != nil {
		t.Fatal(err)
	}
	wire, err := io.ReadAll(input)
	if err != nil || string(wire) != "R" {
		t.Fatal("readiness did not produce one marker followed by EOF")
	}
	if ready.signal() == nil {
		t.Fatal("readiness marker emitted twice")
	}
}

func TestRunReadyAcknowledgesAnActualListenerAndJoinsOnCancel(t *testing.T) {
	p := fixture(t)
	p.config.ListenIP = "127.0.0.2"
	r, err := New(p.config, p.credentials)
	if err != nil {
		t.Fatal(err)
	}
	input, ready := readinessPipe(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.RunReady(ctx, ready) }()
	wire, err := io.ReadAll(input)
	if err != nil || string(wire) != "R" {
		cancel()
		<-done
		t.Fatal("listener startup was not acknowledged")
	}
	client, err := net.DialTimeout("tcp4", "127.0.0.2:15150", time.Second)
	if err != nil {
		cancel()
		<-done
		t.Fatal("readiness preceded a reachable listener")
	}
	client.Close()
	cancel()
	if err := <-done; err != context.Canceled || r.Stats().Active != 0 {
		t.Fatal("ready listener did not join cancellation cleanup")
	}
}

func TestFailedStartupNeverAcknowledgesReadiness(t *testing.T) {
	p := fixture(t)
	input, ready := readinessPipe(t)
	bad := p.credentials
	bad.ServerKeyPEM = []byte("invalid-test-key")
	if _, err := New(p.config, bad); err != ErrCredentials {
		t.Fatal("bad TLS configuration accepted")
	}
	ready.Close() // The entrypoint closes this owner on every constructor error.
	wire, err := io.ReadAll(input)
	if err != nil || len(wire) != 0 {
		t.Fatal("invalid TLS configuration emitted readiness")
	}
	p.config.ListenIP = "127.0.0.3"
	occupied, err := boundedTCPListener("127.0.0.3:15150", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	r, err := New(p.config, p.credentials)
	if err != nil {
		t.Fatal(err)
	}
	input, ready = readinessPipe(t)
	if err := r.RunReady(context.Background(), ready); err != ErrServing {
		t.Fatal("failed listener bind accepted")
	}
	wire, err = io.ReadAll(input)
	if err != nil || len(wire) != 0 || r.Stats().Active != 0 {
		t.Fatal("failed bind acknowledged readiness or retained workers")
	}
}

func TestReadinessWriteFailureClosesTheListener(t *testing.T) {
	p := fixture(t)
	p.config.ListenIP = "127.0.0.4"
	r, err := New(p.config, p.credentials)
	if err != nil {
		t.Fatal(err)
	}
	input, ready := readinessPipe(t)
	input.Close()
	if err := r.RunReady(context.Background(), ready); err != ErrServing || r.Stats().Active != 0 {
		t.Fatal("failed readiness retained a serving worker")
	}
	listener, err := boundedTCPListener("127.0.0.4:15150", 1)
	if err != nil {
		t.Fatal("failed readiness retained the TCP listener")
	}
	listener.Close()
}
