package gateway

import (
	"bufio"
	"context"
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

type Server struct {
	cfg         *config.Config
	policy      *access.Policy
	dialer      upstream.Dialer
	lim         *limiter
	readHeader  time.Duration
	dialTimeout time.Duration
	idleTimeout time.Duration
	mu          sync.Mutex
	active      map[net.Conn]struct{}
	wg          sync.WaitGroup
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
	return &Server{
		cfg:         cfg,
		policy:      policy,
		dialer:      d,
		lim:         newLimiter(cfg.Limits.MaxActive, cfg.Limits.MaxPendingPerClient, cfg.Limits.MaxNewPerSecond),
		readHeader:  time.Duration(cfg.Timeouts.ReadHeaderMs) * time.Millisecond,
		dialTimeout: time.Duration(cfg.Timeouts.DialMs) * time.Millisecond,
		idleTimeout: time.Duration(cfg.Timeouts.TunnelIdleMs) * time.Millisecond,
		active:      make(map[net.Conn]struct{}),
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

func (s *Server) ServeListener(ln net.Listener) error {
	defer ln.Close()
	log.Printf("[gateway] listening (redacted)")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Printf("[gateway] shutdown: stop accepting")
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			default:
			}
			break
		}
		s.mu.Lock()
		s.active[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func(conn net.Conn) {
			defer s.wg.Done()
			defer func() {
				conn.Close()
				s.mu.Lock()
				delete(s.active, conn)
				s.mu.Unlock()
			}()
			s.handleConn(conn)
		}(c)
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		log.Printf("[gateway] drained")
	case <-time.After(10 * time.Second):
		log.Printf("[gateway] force-close remaining")
		s.mu.Lock()
		for c := range s.active {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	}
	return nil
}

func writeStatus(c net.Conn, code int, reason string, extra map[string]string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", code, reason)
	for k, v := range extra {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	sb.WriteString("Content-Length: 0\r\nConnection: close\r\n\r\n")
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, sb.String())
}

func (s *Server) handleConn(raw net.Conn) {
	_ = raw.SetDeadline(time.Now().Add(s.readHeader))
	br := bufio.NewReaderSize(raw, 8192)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	if len(reqLine) > 8192 {
		writeStatus(raw, 400, "Bad Request", nil)
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
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		total += len(line)
		if total > 32768 {
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
			proxyAuth = val
		}
	}
	auth, err := access.Authenticate(s.cfg, proxyAuth)
	if err != nil {
		writeStatus(raw, 407, "Proxy Auth Required", map[string]string{"Proxy-Authenticate": "Basic realm=\"gateway\""})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
	target, err := s.policy.AuthorizeTarget(ctx, authority)
	cancel()
	if err != nil {
		writeStatus(raw, 403, "Forbidden", nil)
		return
	}
	if err := s.lim.acquire(auth.ClientID); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "rate") {
			writeStatus(raw, 429, "Too Many Requests", nil)
		} else {
			writeStatus(raw, 503, "Overloaded", nil)
		}
		return
	}
	released := false
	release := func() {
		if !released {
			released = true
			s.lim.release(auth.ClientID)
		}
	}
	defer release()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), s.dialTimeout+time.Duration(s.cfg.Timeouts.HandshakeMs)*time.Millisecond)
	defer dialCancel()
	up, upBuffered, err := s.dialer.Dial(dialCtx, target)
	if err != nil {
		writeStatus(raw, 502, "Bad Gateway", nil)
		log.Printf("[gateway] client=%s host=%s dial failed", auth.ClientID, target.Hostname)
		return
	}
	defer up.Close()
	var clientPrefix []byte
	if br.Buffered() > 0 {
		n := br.Buffered()
		peeked, _ := br.Peek(n)
		clientPrefix = append([]byte(nil), peeked...)
		_, _ = br.Discard(n)
	}
	_ = raw.SetDeadline(time.Time{})
	raw.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(raw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	if len(upBuffered) > 0 {
		raw.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := raw.Write(upBuffered); err != nil {
			return
		}
	}
	if len(clientPrefix) > 0 {
		up.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := up.Write(clientPrefix); err != nil {
			return
		}
	}
	log.Printf("[gateway] client=%s host=%s tunnel open", auth.ClientID, target.Hostname)
	c2u, u2c := relayTunnel(raw, up, s.idleTimeout)
	log.Printf("[gateway] client=%s host=%s tunnel close c2u=%d u2c=%d", auth.ClientID, target.Hostname, c2u, u2c)
}

func relayTunnel(a, b net.Conn, idle time.Duration) (int64, int64) {
	var c1, c2 int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c1 = copyWithIdle(b, a, idle) }()
	go func() { defer wg.Done(); c2 = copyWithIdle(a, b, idle) }()
	wg.Wait()
	return c1, c2
}

func copyWithIdle(dst, src net.Conn, idle time.Duration) int64 {
	buf := make([]byte, 32768)
	var total int64
	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(10 * time.Second))
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
