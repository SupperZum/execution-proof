package managementrelay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

type pki struct {
	credentials Credentials
	client      tls.Certificate
	roots       *x509.CertPool
	config      Config
}

func differentPin(t *testing.T, pin string) string {
	t.Helper()
	raw, err := hex.DecodeString(pin)
	if err != nil || len(raw) != 48 {
		t.Fatal("invalid fixture SHA-384 pin")
	}
	mask := byte(1)
	if raw[0] == mask {
		mask = 2 // Keep the mutated digest nonzero.
	}
	raw[0] ^= mask
	return hex.EncodeToString(raw)
}

func makeCert(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent = template
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}
func fixture(t *testing.T) pki {
	t.Helper()
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only-server-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caPEM, caKey, _ := makeCert(t, caTemplate, nil, nil)
	caBlock, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"podvm-server"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	serverPEM, _, serverKey := makeCert(t, serverTemplate, ca, caKey)
	// Mirrors CAA NewClientCertificate: self-signed ECDSA P-256, PKCS8,
	// clientAuth, and no SAN. This identity is management-only.
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{Organization: []string{"cloud-api-adaptor"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientPEM, _, clientKey := makeCert(t, clientTemplate, nil, nil)
	client, err := tls.X509KeyPair(clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	c := Config{Version: 1, Purpose: "onb17.gcp-management-tls-relay.v1", ListenIP: "127.0.0.1", ServerName: "podvm-server", ClientCAPEMSHA384: digest(clientPEM), ServerCertPEMSHA384: digest(serverPEM), ClientLeafDERSHA384: digest(client.Certificate[0]), MaxConnections: 2, HandshakeMilliseconds: 400, DialMilliseconds: 200, IdleMilliseconds: 300, SessionMilliseconds: 1500, MaxBytes: 64 << 20}
	return pki{Credentials{clientPEM, serverPEM, serverKey}, client, roots, c}
}
func (p pki) clientTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.roots, ServerName: "podvm-server", Certificates: []tls.Certificate{p.client}}
}

type running struct {
	relay   *Relay
	address string
	cancel  context.CancelFunc
	done    chan error
	backend *net.UnixListener
}

func start(t *testing.T, p pki) *running {
	t.Helper()
	r, err := New(p.config, p.credentials)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "onb17-relay-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "kata.sock")
	backend, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	r.backendPath = path
	listener, err := boundedTCPListener("127.0.0.1:0", p.config.MaxConnections)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.serve(ctx, listener) }()
	s := &running{r, listener.Addr().String(), cancel, done, backend}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("relay workers did not join")
		}
		backend.Close()
		os.RemoveAll(dir)
		if r.Stats().Active != 0 {
			t.Error("active sessions leaked")
		}
	})
	return s
}
func dial(t *testing.T, s *running, config *tls.Config) *tls.Conn {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.address, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	return conn
}
func accept(t *testing.T, s *running) *net.UnixConn {
	t.Helper()
	s.backend.SetDeadline(time.Now().Add(time.Second))
	conn, err := s.backend.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	return conn
}
func frame(stream uint32, kind, flags byte, payload []byte) []byte {
	b := make([]byte, 10+len(payload))
	binary.BigEndian.PutUint32(b[:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(b[4:8], stream)
	b[8] = kind
	b[9] = flags
	copy(b[10:], payload)
	return b
}
func wait(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("bounded condition did not complete")
}

func noBackend(t *testing.T, s *running) {
	t.Helper()
	s.backend.SetDeadline(time.Now().Add(20 * time.Millisecond))
	conn, err := s.backend.AcceptUnix()
	if conn != nil {
		conn.Close()
		t.Fatal("unauthenticated backend connection")
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("backend probe failed: %v", err)
	}
}

func TestTLSRawTTRPCFragmentationMultiplexAndHalfClose(t *testing.T) {
	p := fixture(t)
	s := start(t, p)
	client := dial(t, s, p.clientTLS())
	backend := accept(t, s)
	// Exact v1.2.7 ttrpc big-endian ten-byte headers, multiple stream IDs,
	// fragmented and coalesced data. The relay never parses or changes them.
	request := append(frame(1, 1, 0, []byte{0x0a, 0x01, 'x'}), frame(3, 3, 2, []byte{1, 2, 3, 4})...)
	for _, fragment := range [][]byte{request[:1], request[1:7], request[7:]} {
		if _, err := client.Write(fragment); err != nil {
			t.Fatal(err)
		}
	}
	got := make([]byte, len(request))
	if _, err := io.ReadFull(backend, got); err != nil || !bytes.Equal(got, request) {
		t.Fatalf("raw request mismatch: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	if n, err := backend.Read(one); n != 0 || err != io.EOF {
		t.Fatalf("client half-close missing: %d %v", n, err)
	}
	response := append(frame(3, 2, 0, []byte("three")), frame(1, 2, 1, []byte("one"))...)
	if _, err := backend.Write(response); err != nil {
		t.Fatal(err)
	}
	backend.CloseWrite()
	got = make([]byte, len(response))
	if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, response) {
		t.Fatalf("raw response mismatch: %v", err)
	}
	if n, err := client.Read(one); n != 0 || err != io.EOF {
		t.Fatalf("server half-close missing: %d %v", n, err)
	}
	wait(t, func() bool { return s.relay.Stats().Active == 0 })
	if s.relay.Stats().BackendConnections != 1 {
		t.Fatal("wrong backend count")
	}
}
func TestWrongMissingClientCertAndTLS12NeverReachBackend(t *testing.T) {
	for _, mode := range []string{"missing", "foreign", "tls12", "wrong-pin"} {
		t.Run(mode, func(t *testing.T) {
			p := fixture(t)
			config := p.clientTLS()
			switch mode {
			case "missing":
				config.Certificates = nil
			case "foreign":
				config.Certificates = []tls.Certificate{fixture(t).client}
			case "tls12":
				config.MaxVersion = tls.VersionTLS12
			case "wrong-pin":
				p.config.ClientLeafDERSHA384 = differentPin(t, p.config.ClientLeafDERSHA384)
			}
			s := start(t, p)
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.address, config)
			if err == nil {
				conn.SetDeadline(time.Now().Add(time.Second))
				_, err = conn.Read(make([]byte, 1))
				conn.Close()
			}
			if err == nil {
				t.Fatal("unauthenticated TLS accepted")
			}
			wait(t, func() bool { return s.relay.Stats().Active == 0 })
			if s.relay.Stats().BackendConnections != 0 {
				t.Fatal("backend opened before authentication")
			}
			noBackend(t, s)
		})
	}
}
func TestWrongServerCAAndSANAreRejected(t *testing.T) {
	for _, mode := range []string{"ca", "san"} {
		t.Run(mode, func(t *testing.T) {
			p := fixture(t)
			s := start(t, p)
			config := p.clientTLS()
			if mode == "ca" {
				config.RootCAs = fixture(t).roots
			} else {
				config.ServerName = "foreign-server"
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.address, config)
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("server trust mismatch accepted")
			}
			wait(t, func() bool { return s.relay.Stats().Active == 0 })
			if s.relay.Stats().BackendConnections != 0 {
				t.Fatal("backend opened after rejected server handshake")
			}
		})
	}
}
func TestStalledHandshakeAndSaturationAreBounded(t *testing.T) {
	p := fixture(t)
	p.config.MaxConnections = 1
	p.config.HandshakeMilliseconds = 80
	s := start(t, p)
	first, err := net.Dial("tcp", s.address)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	wait(t, func() bool { return s.relay.Stats().Active == 1 })
	second, err := net.DialTimeout("tcp", s.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	time.Sleep(20 * time.Millisecond)
	if s.relay.Stats().Accepted != 1 || s.relay.Stats().Active != 1 {
		t.Fatal("unbounded accepted connections")
	}
	wait(t, func() bool { return s.relay.Stats().Accepted == 2 })
	wait(t, func() bool { return s.relay.Stats().Active == 0 })
	if s.relay.Stats().BackendConnections != 0 {
		t.Fatal("stalled unauthenticated client reached backend")
	}
}
func TestIdleTotalAndTransferLimitsCloseAndJoin(t *testing.T) {
	for _, mode := range []string{"idle", "total", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			p := fixture(t)
			p.config.IdleMilliseconds = 80
			if mode == "total" {
				p.config.HandshakeMilliseconds = 80
				p.config.DialMilliseconds = 80
				p.config.IdleMilliseconds = 100
				p.config.SessionMilliseconds = 180
			}
			if mode == "bytes" {
				p.config.MaxBytes = 8
			}
			s := start(t, p)
			client := dial(t, s, p.clientTLS())
			backend := accept(t, s)
			if mode == "bytes" {
				client.Write(bytes.Repeat([]byte{1}, 32))
			} else if mode == "total" {
				var traffic sync.WaitGroup
				traffic.Add(1)
				go func() {
					defer traffic.Done()
					for range 15 {
						if _, err := client.Write([]byte{1}); err != nil {
							return
						}
						time.Sleep(20 * time.Millisecond)
					}
				}()
				buf := make([]byte, 1)
				for {
					if _, err := backend.Read(buf); err != nil {
						break
					}
				}
				traffic.Wait()
			}
			wait(t, func() bool { return s.relay.Stats().Active == 0 })
			if mode == "bytes" && s.relay.Stats().TransferredBytes > 8 {
				t.Fatal("transfer budget exceeded")
			}
		})
	}
}

func TestPendingCreateResponseAndIdleBudget(t *testing.T) {
	for _, profile := range []struct {
		name string
		idle int
	}{
		{"short-idle-timeout", 1000},
		{"long-idle-timeout", 30000},
	} {
		t.Run(profile.name, func(t *testing.T) {
			p := fixture(t)
			p.config.IdleMilliseconds = profile.idle
			p.config.SessionMilliseconds = 300000
			p.config.SandboxGateway = true
			s := start(t, p)
			client := dial(t, s, p.clientTLS())
			backend := accept(t, s)
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := backend.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}

			request := frame(1, 1, 0, []byte("pending create"))
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(request))
			if _, err := io.ReadFull(backend, got); err != nil || !bytes.Equal(got, request) {
				t.Fatalf("request did not reach the gateway: %v", err)
			}
			if profile.idle == 1000 {
				wait(t, func() bool { return s.relay.Stats().Active == 0 })
				if n, err := client.Read(got); n != 0 || err == nil {
					t.Fatalf("expected relay disconnect while the response was pending: %d %v", n, err)
				}
				return
			}

			time.Sleep(1800 * time.Millisecond)
			response := frame(1, 2, 0, []byte("admitted"))
			if _, err := backend.Write(response); err != nil {
				t.Fatal(err)
			}
			got = make([]byte, len(response))
			if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, response) {
				t.Fatalf("delayed response did not reach the client: %v", err)
			}
		})
	}
}

func TestShutdownJoinsDuringHandshakeAndEstablishedCopy(t *testing.T) {
	for _, phase := range []string{"handshake", "copy"} {
		t.Run(phase, func(t *testing.T) {
			p := fixture(t)
			s := start(t, p)
			if phase == "handshake" {
				conn, err := net.Dial("tcp", s.address)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
			} else {
				dial(t, s, p.clientTLS())
				accept(t, s)
			}
			wait(t, func() bool { return s.relay.Stats().Active == 1 })
			s.cancel()
			wait(t, func() bool { return s.relay.Stats().Active == 0 })
		})
	}
}
func TestBackendFailureCannotSelectAnotherDestination(t *testing.T) {
	p := fixture(t)
	s := start(t, p)
	s.backend.Close()
	client := dial(t, s, p.clientTLS())
	_, err := client.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("missing backend produced success")
	}
	wait(t, func() bool { return s.relay.Stats().Active == 0 })
	if s.relay.Stats().BackendConnections != 0 {
		t.Fatal("unexpected backend connection")
	}
	if BackendSocket != "/run/onb17/kata-agent.sock" {
		t.Fatal("fixed backend changed")
	}
}
func TestStrictConfigAndCredentialPins(t *testing.T) {
	p := fixture(t)
	wire, _ := json.Marshal(p.config)
	if _, err := DecodeConfig(wire); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(wire, []byte(" {}")...), bytes.Replace(wire, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(wire, []byte(`"version":1`), []byte(`"version":1,"backend":"/tmp/x"`), 1), bytes.Repeat([]byte{' '}, MaxConfigBytes+1), bytes.Replace(wire, []byte(`"version":1`), []byte(`"VERSION":1`), 1)} {
		if _, err := DecodeConfig(bad); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.MaxConnections = 9 },
		func(c *Config) { c.ListenIP = "hostname.example" },
		func(c *Config) { c.ServerName = "wrong-san" },
		func(c *Config) { c.ClientCAPEMSHA384 = differentPin(t, c.ClientCAPEMSHA384) },
	} {
		c := p.config
		change(&c)
		if _, err := New(c, p.credentials); err == nil {
			t.Fatal("invalid startup selection accepted")
		}
	}
	bad := p.credentials
	bad.ServerKeyPEM = []byte("test-secret-not-a-key")
	if _, err := New(p.config, bad); err != ErrCredentials || bytes.Contains([]byte(err.Error()), bad.ServerKeyPEM) {
		t.Fatal("credential failure leaked data or succeeded")
	}
}

func TestSharedRustPublicConfigurationShape(t *testing.T) {
	wire, err := os.ReadFile("../../contract/tests/fixtures/gcp-management-relay/public-config-shape.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := DecodeConfig(wire)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(wire)) {
		t.Fatal("Rust/Go public config shape mismatch")
	}
}

func TestMeasuredSandboxGatewaySelectsFixedBackend(t *testing.T) {
	p := fixture(t)
	for _, selected := range []bool{false, true} {
		p.config.SandboxGateway = selected
		wire, err := json.Marshal(p.config)
		if err != nil {
			t.Fatal(err)
		}
		c, err := DecodeConfig(wire)
		if err != nil {
			t.Fatal(err)
		}
		r, err := New(c, p.credentials)
		if err != nil {
			t.Fatal(err)
		}
		want := BackendSocket
		if selected {
			want = SandboxGatewaySocket
		}
		if r.backendPath != want {
			t.Fatalf("selected backend %q; want %q", r.backendPath, want)
		}
		if selected {
			for _, invalid := range []string{`"sandbox_gateway":null`, `"sandbox_gateway":"true"`, `"sandbox_gateway":true,"sandbox_gateway":false`} {
				mutated := bytes.Replace(wire, []byte(`"sandbox_gateway":true`), []byte(invalid), 1)
				if _, err := DecodeConfig(mutated); err == nil {
					t.Fatal("invalid sandbox selection accepted")
				}
			}
		}
	}
}

func TestEd25519ManagementLeavesCannotReuseProofKeyAlgorithm(t *testing.T) {
	for _, role := range []string{"server", "client"} {
		t.Run(role, func(t *testing.T) {
			p := fixture(t)
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			template := &x509.Certificate{SerialNumber: big.NewInt(11), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			if role == "server" {
				template.DNSNames = []string{"podvm-server"}
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
			if err != nil {
				t.Fatal(err)
			}
			keyDER, err := x509.MarshalPKCS8PrivateKey(private)
			if err != nil {
				t.Fatal(err)
			}
			cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
			if role == "server" {
				p.credentials.ServerCertPEM = cert
				p.credentials.ServerKeyPEM = key
				p.config.ServerCertPEMSHA384 = digest(cert)
				if _, err := New(p.config, p.credentials); err != ErrCredentials {
					t.Fatal("Ed25519 server key accepted")
				}
				return
			}
			pair, err := tls.X509KeyPair(cert, key)
			if err != nil {
				t.Fatal(err)
			}
			p.client = pair
			p.credentials.ClientCAPEM = cert
			p.config.ClientCAPEMSHA384 = digest(cert)
			p.config.ClientLeafDERSHA384 = digest(der)
			s := start(t, p)
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.address, p.clientTLS())
			if err == nil {
				conn.SetDeadline(time.Now().Add(time.Second))
				_, err = conn.Read(make([]byte, 1))
				conn.Close()
			}
			if err == nil {
				t.Fatal("Ed25519 client key accepted")
			}
			wait(t, func() bool { return s.relay.Stats().Active == 0 })
			noBackend(t, s)
		})
	}
}

func fillBackend(t *testing.T, s *running) {
	t.Helper()
	raw, err := s.backend.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var result error
	if err := raw.Control(func(fd uintptr) { result = syscall.Listen(int(fd), 0) }); err != nil || result != nil {
		t.Fatal("backend backlog setup failed")
	}
	pending, err := net.DialTimeout("unix", s.relay.backendPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pending.Close() })
}
func TestBackendDialDeadlineAndShutdownJoin(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "shutdown"}[shutdown], func(t *testing.T) {
			p := fixture(t)
			p.config.DialMilliseconds = 80
			s := start(t, p)
			fillBackend(t, s)
			client := dial(t, s, p.clientTLS())
			wait(t, func() bool { return s.relay.Stats().Authenticated == 1 })
			if shutdown {
				s.cancel()
			}
			if _, err := client.Read(make([]byte, 1)); err == nil {
				t.Fatal("saturated backend produced success")
			}
			wait(t, func() bool { return s.relay.Stats().Active == 0 })
			if s.relay.Stats().BackendConnections != 0 {
				t.Fatal("unexpected backend dial success")
			}
		})
	}
}
func TestStalledBackendWriteTerminatesAndJoins(t *testing.T) {
	p := fixture(t)
	p.config.IdleMilliseconds = 80
	s := start(t, p)
	client := dial(t, s, p.clientTLS())
	accept(t, s)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = client.Write(make([]byte, 2<<20)) }()
	wait(t, func() bool { return s.relay.Stats().Active == 0 })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked client writer leaked")
	}
}
func TestMatchedExpiredClientAndExpiredServerAreRejected(t *testing.T) {
	p := fixture(t)
	now := time.Now()
	expired := &x509.Certificate{SerialNumber: big.NewInt(9), NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	cert, _, key := makeCert(t, expired, nil, nil)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	p.client = pair
	p.credentials.ClientCAPEM = cert
	p.config.ClientCAPEMSHA384 = digest(cert)
	p.config.ClientLeafDERSHA384 = digest(pair.Certificate[0])
	s := start(t, p)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.address, p.clientTLS())
	if err == nil {
		conn.SetDeadline(time.Now().Add(time.Second))
		_, err = conn.Read(make([]byte, 1))
		conn.Close()
	}
	if err == nil {
		t.Fatal("expired client accepted")
	}
	wait(t, func() bool { return s.relay.Stats().Active == 0 })
	noBackend(t, s)
	p = fixture(t)
	expired.DNSNames = []string{"podvm-server"}
	expired.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	cert, _, key = makeCert(t, expired, nil, nil)
	p.credentials.ServerCertPEM = cert
	p.credentials.ServerKeyPEM = key
	p.config.ServerCertPEMSHA384 = digest(cert)
	if _, err := New(p.config, p.credentials); err != ErrCredentials {
		t.Fatal("expired server certificate accepted")
	}
}
