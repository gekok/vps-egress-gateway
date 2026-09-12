package gateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
	"github.com/gekok/vps-egress-gateway/internal/config"
	"github.com/gekok/vps-egress-gateway/internal/upstream"
)

const (
	maxRequestLineBytes = 8192
	maxHeaderBytes      = 32768
	statusWriteTimeout  = 5 * time.Second
	relayWriteTimeout   = 10 * time.Second

	defaultDrainGrace = 10 * time.Second
	defaultDrainHard  = 5 * time.Second
)

type Server struct {
	cfg         *config.Config
	policy      *access.Policy
	dialer      upstream.Dialer
	lim         *limiter
	readHeader  time.Duration
	dialTimeout time.Duration
	idleTimeout time.Duration
	relayBuf    int

	// DrainGrace is how long shutdown waits for tunnels to end on their own.
	// DrainHard bounds the wait after every tracked conn has been force-closed,
	// so shutdown cannot block on a stuck relay.
	DrainGrace time.Duration
	DrainHard  time.Duration

	mu       sync.Mutex
	active   map[net.Conn]struct{}
	draining bool
	wg       sync.WaitGroup

	// pending bounds connections accepted but not yet relaying, so
	// unauthenticated peers cannot each pin a header buffer.
	pending chan struct{}

	// forceCtx is cancelled when drain() starts force-closing, so a handler
	// parked in DNS or an upstream dial gives up instead of outliving DrainHard.
	forceCtx    context.Context
	forceCancel context.CancelFunc

	quitOnce sync.Once
	quit     chan struct{}
	lnMu     sync.Mutex
	ln       net.Listener
}

func New(cfg *config.Config) (*Server, error) {
	return NewWithDeps(cfg, nil, nil)
}

func NewWithDeps(cfg *config.Config, policy *access.Policy, d upstream.Dialer) (*Server, error) {
	if policy == nil {
		policy = access.NewPolicy(cfg, nil)
	}
	var err error
	if d == nil {
		d, err = upstream.NewDialer(cfg)
		if err != nil {
			return nil, err
		}
	}
	buf := cfg.Limits.MaxBufferBytes
	if buf <= 0 {
		buf = 32 * 1024
	}
	pendingSlots := cfg.Limits.MaxPendingHandshakes
	if pendingSlots <= 0 {
		pendingSlots = 4 * cfg.Limits.MaxActive
	}
	if pendingSlots <= 0 {
		pendingSlots = 64
	}
	forceCtx, forceCancel := context.WithCancel(context.Background())
	return &Server{
		cfg:         cfg,
		policy:      policy,
		dialer:      d,
		lim:         newLimiter(cfg.Limits.MaxActive, cfg.Limits.MaxPendingPerClient, cfg.Limits.MaxNewPerSecond),
		readHeader:  time.Duration(cfg.Timeouts.ReadHeaderMs) * time.Millisecond,
		dialTimeout: time.Duration(cfg.Timeouts.DialMs) * time.Millisecond,
		idleTimeout: time.Duration(cfg.Timeouts.TunnelIdleMs) * time.Millisecond,
		relayBuf:    buf,
		DrainGrace:  defaultDrainGrace,
		DrainHard:   defaultDrainHard,
		active:      make(map[net.Conn]struct{}),
		pending:     make(chan struct{}, pendingSlots),
		forceCtx:    forceCtx,
		forceCancel: forceCancel,
		quit:        make(chan struct{}),
	}, nil
}

func Serve(cfg *config.Config) error {
	s, err := New(cfg)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return s.ServeListener(ln)
}

// Shutdown stops accepting new connections and starts the drain sequence in
// ServeListener. It is safe to call more than once and from any goroutine.
func (s *Server) Shutdown() {
	s.quitOnce.Do(func() { close(s.quit) })
	s.lnMu.Lock()
	ln := s.ln
	s.lnMu.Unlock()
	if ln != nil {
		ln.Close()
	}
}

// track registers a conn for force-close. It reports false once drain has begun,
// in which case the conn is closed straight away and the caller must give up:
// otherwise a conn created during the force-close pass would never be closed.
func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	if s.draining {
		s.mu.Unlock()
		_ = c.SetDeadline(time.Now())
		_ = c.Close()
		return false
	}
	s.active[c] = struct{}{}
	s.mu.Unlock()
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.active, c)
	s.mu.Unlock()
}

func (s *Server) closeAllTracked() {
	s.mu.Lock()
	s.draining = true
	conns := make([]net.Conn, 0, len(s.active))
	for c := range s.active {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.SetDeadline(time.Now())
		_ = c.Close()
	}
}

func (s *Server) ServeListener(ln net.Listener) error {
	s.lnMu.Lock()
	s.ln = ln
	s.lnMu.Unlock()
	defer ln.Close()
	// Release forceCtx even when the drain finishes inside its grace period and
	// never reaches the force-close branch.
	defer s.forceCancel()
	// Shutdown may have run before the listener was registered, in which case it
	// found a nil listener and could not close it.
	select {
	case <-s.quit:
		ln.Close()
	default:
	}
	log.Printf("[gateway] listening (redacted)")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	go func() {
		select {
		case <-stop:
			log.Printf("[gateway] shutdown: stop accepting")
			s.Shutdown()
		case <-s.quit:
		}
	}()
	var acceptDelay time.Duration
acceptLoop:
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break acceptLoop
			}
			select {
			case <-s.quit:
				break acceptLoop
			default:
			}
			// A transient accept error (fd exhaustion, a peer that reset before
			// we accepted it) must not take the listener down for good.
			if acceptDelay == 0 {
				acceptDelay = 5 * time.Millisecond
			} else if acceptDelay *= 2; acceptDelay > time.Second {
				acceptDelay = time.Second
			}
			log.Printf("[gateway] accept error, retrying in %v: %v", acceptDelay, err)
			t := time.NewTimer(acceptDelay)
			select {
			case <-t.C:
			case <-s.quit:
				t.Stop()
				break acceptLoop
			}
			continue
		}
		acceptDelay = 0
		if !s.track(c) {
			continue
		}
		s.wg.Add(1)
		go func(conn net.Conn) {
			defer s.wg.Done()
			defer func() {
				conn.Close()
				s.untrack(conn)
			}()
			s.handleConn(conn)
		}(c)
	}
	s.quitOnce.Do(func() { close(s.quit) })
	return s.drain()
}

// drain waits for live tunnels, then force-closes whatever is left so the
// process cannot be held open by an idle tunnel or a stuck upstream.
func (s *Server) drain() error {
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		log.Printf("[gateway] drained")
		return nil
	case <-time.After(s.DrainGrace):
	}
	log.Printf("[gateway] force-close remaining")
	s.forceCancel()
	s.closeAllTracked()
	select {
	case <-done:
		log.Printf("[gateway] drained after force-close")
		return nil
	case <-time.After(s.DrainHard):
		log.Printf("[gateway] drain timeout: handlers still running")
		return fmt.Errorf("shutdown drain timed out")
	}
}

func writeStatus(c net.Conn, code int, reason string, extra map[string]string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", code, reason)
	for k, v := range extra {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	sb.WriteString("Content-Length: 0\r\nConnection: close\r\n\r\n")
	c.SetWriteDeadline(time.Now().Add(statusWriteTimeout))
	_, _ = io.WriteString(c, sb.String())
}

var errLineTooLong = errors.New("line too long")

// readLineLimited reads one '\r\n'-terminated line while capping how many bytes
// a client that never sends a newline can make us buffer.
func readLineLimited(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		chunk, err := br.ReadSlice('\n')
		if sb.Len()+len(chunk) > max {
			return "", errLineTooLong
		}
		sb.Write(chunk)
		if err == nil {
			return sb.String(), nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return "", err
	}
}

func (s *Server) handleConn(raw net.Conn) {
	// Hold a pending slot until this connection either fails or becomes a
	// tunnel. Past that point max_active governs.
	select {
	case s.pending <- struct{}{}:
	default:
		writeStatus(raw, 503, "Overloaded", nil)
		return
	}
	var releaseOnce sync.Once
	releasePending := func() { releaseOnce.Do(func() { <-s.pending }) }
	defer releasePending()

	_ = raw.SetDeadline(time.Now().Add(s.readHeader))
	br := bufio.NewReaderSize(raw, 8192)
	reqLine, err := readLineLimited(br, maxRequestLineBytes)
	if err != nil {
		if err == errLineTooLong {
			writeStatus(raw, 431, "Request Line Too Large", nil)
		}
		return
	}
	parts := strings.SplitN(strings.TrimSpace(reqLine), " ", 3)
	if len(parts) != 3 || parts[0] != "CONNECT" {
		writeStatus(raw, 400, "Bad Request", nil)
		return
	}
	if parts[2] != "HTTP/1.1" && parts[2] != "HTTP/1.0" {
		writeStatus(raw, 400, "Bad Request", nil)
		return
	}
	authority := parts[1]
	var proxyAuth string
	total := 0
	for {
		line, err := readLineLimited(br, maxHeaderBytes)
		if err != nil {
			if err == errLineTooLong {
				writeStatus(raw, 431, "Header Too Large", nil)
			}
			return
		}
		total += len(line)
		if total > maxHeaderBytes {
			writeStatus(raw, 431, "Header Too Large", nil)
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			writeStatus(raw, 400, "Bad Request", nil)
			return
		}
		name := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if strings.EqualFold(name, "Proxy-Authorization") {
			// Two credentials in one request is ambiguous; refuse rather than
			// silently picking the last one.
			if proxyAuth != "" {
				writeStatus(raw, 400, "Bad Request", nil)
				return
			}
			proxyAuth = val
		}
	}
	auth, err := access.Authenticate(s.cfg, proxyAuth)
	if err != nil {
		writeStatus(raw, 407, "Proxy Auth Required", map[string]string{"Proxy-Authenticate": "Basic realm=\"gateway\""})
		return
	}
	ctx, cancel := context.WithTimeout(s.forceCtx, s.dialTimeout)
	target, err := s.policy.AuthorizeTarget(ctx, authority)
	cancel()
	if err != nil {
		writeStatus(raw, 403, "Forbidden", nil)
		return
	}
	if err := s.lim.acquire(auth.ClientID); err != nil {
		if strings.Contains(err.Error(), "rate") {
			writeStatus(raw, 429, "Too Many Requests", nil)
		} else {
			writeStatus(raw, 503, "Overloaded", nil)
		}
		return
	}
	defer s.lim.release(auth.ClientID)
	dialCtx, dialCancel := context.WithTimeout(s.forceCtx, s.dialTimeout+time.Duration(s.cfg.Timeouts.HandshakeMs)*time.Millisecond)
	defer dialCancel()
	up, upBuffered, err := s.dialer.Dial(dialCtx, target)
	if err != nil {
		writeStatus(raw, 502, "Bad Gateway", nil)
		// The cause stays in the gateway log; the client only ever sees 502.
		log.Printf("[gateway] client=%s host=%s dial failed: %v", auth.ClientID, target.Hostname, err)
		return
	}
	// Tracked so shutdown can force-close the upstream leg too; otherwise the
	// upstream-to-client copy keeps blocking until tunnel_idle_ms expires.
	if !s.track(up) {
		return
	}
	defer func() {
		up.Close()
		s.untrack(up)
	}()
	var clientPrefix []byte
	if n := br.Buffered(); n > 0 {
		peeked, _ := br.Peek(n)
		clientPrefix = append([]byte(nil), peeked...)
		_, _ = br.Discard(n)
	}
	_ = raw.SetDeadline(time.Time{})
	raw.SetWriteDeadline(time.Now().Add(statusWriteTimeout))
	if _, err := io.WriteString(raw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	if len(upBuffered) > 0 {
		raw.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
		if _, err := raw.Write(upBuffered); err != nil {
			return
		}
	}
	if len(clientPrefix) > 0 {
		up.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
		if _, err := up.Write(clientPrefix); err != nil {
			return
		}
	}
	log.Printf("[gateway] client=%s host=%s tunnel open", auth.ClientID, target.Hostname)
	releasePending()
	c2u, u2c := relayTunnel(raw, up, s.idleTimeout, s.relayBuf)
	log.Printf("[gateway] client=%s host=%s tunnel close c2u=%d u2c=%d", auth.ClientID, target.Hostname, c2u, u2c)
}

// relayTunnel copies opaque bytes both ways. A direction that outlives its
// peer is bounded by tunnel_idle_ms, and by the force-close in drain().
func relayTunnel(a, b net.Conn, idle time.Duration, bufSize int) (int64, int64) {
	var c1, c2 int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c1 = copyWithIdle(b, a, idle, bufSize) }()
	go func() { defer wg.Done(); c2 = copyWithIdle(a, b, idle, bufSize) }()
	wg.Wait()
	return c1, c2
}

func copyWithIdle(dst, src net.Conn, idle time.Duration, bufSize int) int64 {
	if bufSize <= 0 {
		bufSize = 32 * 1024
	}
	buf := make([]byte, bufSize)
	var total int64
	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				break
			}
			total += int64(n)
		}
		if rerr != nil {
			break
		}
	}
	return total
}

func (s *Server) ActiveCount() int {
	n, _ := s.lim.counts()
	return n
}
