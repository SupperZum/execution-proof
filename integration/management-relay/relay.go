package managementrelay

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type relayBuffers struct{ up, down [BufferBytes]byte }
type session struct {
	client  net.Conn
	backend net.Conn
	end     time.Time
}
type Relay struct {
	config                                                 Config
	tlsConfig                                              *tls.Config
	backendPath                                            string
	buffers                                                chan *relayBuffers
	running                                                atomic.Bool
	mu                                                     sync.Mutex
	sessions                                               map[*session]struct{}
	accepted, authenticated, backends, active, transferred atomic.Int64
}
type Stats struct{ Accepted, Authenticated, BackendConnections, Active, TransferredBytes int64 }

func (r *Relay) Stats() Stats {
	return Stats{r.accepted.Load(), r.authenticated.Load(), r.backends.Load(), r.active.Load(), r.transferred.Load()}
}

// New allocates the bounded copy buffers before any listener is opened. It
// accepts trusted startup data, not a caller-provided dialer or backend target.
func New(c Config, credentials Credentials) (*Relay, error) {
	if c.validate() != nil {
		return nil, ErrConfiguration
	}
	tc, err := tlsConfiguration(c, credentials)
	if err != nil {
		return nil, err
	}
	backend := BackendSocket
	if c.SandboxGateway {
		backend = SandboxGatewaySocket
	}
	r := &Relay{config: c, tlsConfig: tc, backendPath: backend, buffers: make(chan *relayBuffers, c.MaxConnections), sessions: make(map[*session]struct{}, c.MaxConnections)}
	for range c.MaxConnections {
		r.buffers <- new(relayBuffers)
	}
	return r, nil
}
func (r *Relay) Run(ctx context.Context) error {
	return r.run(ctx, nil)
}

// RunReady consumes a private startup pipe. The parent receives its one-byte
// acknowledgement only after New validated TLS and the TCP listener is open.
func (r *Relay) RunReady(ctx context.Context, ready *StartupReadiness) error {
	if ready == nil || ready.file == nil {
		return ErrConfiguration
	}
	defer ready.Close()
	return r.run(ctx, ready)
}

func (r *Relay) run(ctx context.Context, ready *StartupReadiness) error {
	if !r.running.CompareAndSwap(false, true) {
		return ErrServing
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	listener, err := boundedTCPListener(net.JoinHostPort(r.config.ListenIP, strconv.Itoa(ListenPort)), r.config.MaxConnections)
	if err != nil {
		return ErrServing
	}
	defer listener.Close()
	if ready != nil && ready.signal() != nil {
		return ErrServing
	}
	return r.serve(ctx, listener)
}
func (r *Relay) closeSessions() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for s := range r.sessions {
		_ = s.client.Close()
		if s.backend != nil {
			_ = s.backend.Close()
		}
	}
}
func (r *Relay) serve(ctx context.Context, listener *net.TCPListener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ownerDone, watchDone := make(chan struct{}), make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
		case <-ownerDone:
		}
		_ = listener.Close()
		r.closeSessions()
	}()
	var result error
	for {
		var buffers *relayBuffers
		select {
		case <-ctx.Done():
			result = ctx.Err()
		case buffers = <-r.buffers:
		}
		if result != nil {
			break
		}
		client, err := listener.AcceptTCP()
		if err != nil {
			r.buffers <- buffers
			if ctx.Err() != nil {
				result = ctx.Err()
			} else {
				result = ErrServing
			}
			break
		}
		s := &session{client: client, end: time.Now().Add(milliseconds(r.config.SessionMilliseconds))}
		r.mu.Lock()
		if ctx.Err() != nil {
			r.mu.Unlock()
			_ = client.Close()
			r.buffers <- buffers
			result = ctx.Err()
			break
		}
		r.sessions[s] = struct{}{}
		r.mu.Unlock()
		r.accepted.Add(1)
		r.active.Add(1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() {
				_ = s.client.Close()
				r.mu.Lock()
				if s.backend != nil {
					_ = s.backend.Close()
				}
				delete(r.sessions, s)
				r.mu.Unlock()
				r.active.Add(-1)
				r.buffers <- buffers
			}()
			r.handle(ctx, s, buffers)
		}()
	}
	cancel()
	close(ownerDone)
	_ = listener.Close()
	r.closeSessions()
	workers.Wait()
	<-watchDone
	return result
}
func milliseconds(value int) time.Duration { return time.Duration(value) * time.Millisecond }
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (r *Relay) handle(ctx context.Context, s *session, buffers *relayBuffers) {
	end := s.end
	handshakeEnd := earlier(end, time.Now().Add(milliseconds(r.config.HandshakeMilliseconds)))
	_ = s.client.SetDeadline(handshakeEnd)
	bounded := &handshakeConn{Conn: s.client}
	bounded.readLeft.Store(64 << 10)
	bounded.writeLeft.Store(64 << 10)
	bounded.enabled.Store(true)
	client := tls.Server(bounded, r.tlsConfig)
	handshakeCtx, cancel := context.WithDeadline(ctx, handshakeEnd)
	err := client.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		return
	}
	bounded.enabled.Store(false)
	r.authenticated.Add(1)
	dialCtx, cancel := context.WithDeadline(ctx, earlier(end, time.Now().Add(milliseconds(r.config.DialMilliseconds))))
	backend, err := (&net.Dialer{}).DialContext(dialCtx, "unix", r.backendPath)
	cancel()
	if err != nil {
		return
	}
	r.mu.Lock()
	if ctx.Err() != nil {
		r.mu.Unlock()
		_ = backend.Close()
		return
	}
	s.backend = backend
	r.mu.Unlock()
	r.backends.Add(1)
	_ = client.SetDeadline(end)
	_ = backend.SetDeadline(end)
	var remaining atomic.Int64
	remaining.Store(r.config.MaxBytes)
	results := make(chan error, 2)
	go func() { results <- r.copyStream(backend, client, buffers.up[:], &remaining, end) }()
	go func() { results <- r.copyStream(client, backend, buffers.down[:], &remaining, end) }()
	if first := <-results; first != nil {
		_ = s.client.Close()
		_ = backend.Close()
	}
	<-results
}
func (r *Relay) copyStream(dst, src net.Conn, buffer []byte, remaining *atomic.Int64, end time.Time) error {
	for {
		if err := src.SetReadDeadline(earlier(end, time.Now().Add(milliseconds(r.config.IdleMilliseconds)))); err != nil {
			return err
		}
		n, readErr := src.Read(buffer)
		if n > 0 {
			for {
				available := remaining.Load()
				if int64(n) > available {
					return ErrBudget
				}
				if remaining.CompareAndSwap(available, available-int64(n)) {
					break
				}
			}
			if err := dst.SetWriteDeadline(earlier(end, time.Now().Add(milliseconds(r.config.IdleMilliseconds)))); err != nil {
				return err
			}
			sent := 0
			for sent < n {
				m, err := dst.Write(buffer[sent:n])
				sent += m
				r.transferred.Add(int64(m))
				if err != nil {
					return err
				}
				if m == 0 {
					return io.ErrNoProgress
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if err := dst.SetWriteDeadline(earlier(end, time.Now().Add(milliseconds(r.config.IdleMilliseconds)))); err != nil {
					return err
				}
				if half, ok := dst.(interface{ CloseWrite() error }); ok {
					return half.CloseWrite()
				}
				return io.ErrClosedPipe
			}
			return readErr
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
}

// Both TLS directions have a small handshake wire ceiling. TLS itself applies
// its protocol message/record limits; application copies use the separate cap.
type handshakeConn struct {
	net.Conn
	enabled             atomic.Bool
	readLeft, writeLeft atomic.Int64
}

func (c *handshakeConn) Read(p []byte) (int, error) {
	if !c.enabled.Load() {
		return c.Conn.Read(p)
	}
	left := c.readLeft.Load()
	if left <= 0 {
		return 0, ErrBudget
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, err := c.Conn.Read(p)
	c.readLeft.Add(-int64(n))
	return n, err
}
func (c *handshakeConn) Write(p []byte) (int, error) {
	if !c.enabled.Load() {
		return c.Conn.Write(p)
	}
	if int64(len(p)) > c.writeLeft.Load() {
		return 0, ErrBudget
	}
	n, err := c.Conn.Write(p)
	c.writeLeft.Add(-int64(n))
	return n, err
}
