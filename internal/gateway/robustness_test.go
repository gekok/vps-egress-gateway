package gateway

import (
	"bufio"
	"context"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
	"github.com/gekok/vps-egress-gateway/internal/config"
	"github.com/gekok/vps-egress-gateway/internal/testutil"
)

type endlessReader struct{ b byte }

func (e endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = e.b
	}
	return len(p), nil
}

// TestReadLineLimitedBoundsUnterminatedLine pins the memory bound: a peer that
// never sends a newline must not be able to grow our buffer without limit.
func TestReadLineLimitedBoundsUnterminatedLine(t *testing.T) {
	br := bufio.NewReaderSize(endlessReader{b: 'A'}, 4096)
	done := make(chan error, 1)
	go func() {
		_, err := readLineLimited(br, maxHeaderBytes)
		done <- err
	}()
	select {
	case err := <-done:
		if err != errLineTooLong {
			t.Fatalf("err = %v, want errLineTooLong", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("readLineLimited did not stop on an endless line")
	}
}

func TestReadLineLimitedShortLine(t *testing.T) {
	br := bufio.NewReaderSize(strings.NewReader("CONNECT example.com:443 HTTP/1.1\r\n"), 8)
	got, err := readLineLimited(br, maxRequestLineBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "CONNECT example.com:443 HTTP/1.1\r\n" {
		t.Fatalf("got %q", got)
	}
}

// writeJunk sends exactly n bytes containing no newline. The count is chosen so
// the gateway consumes all of them before refusing, which keeps the 431 from
// being lost to a reset on close.
func writeJunk(t *testing.T, c net.Conn, n int) {
	t.Helper()
	c.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(strings.Repeat("A", n))); err != nil {
		t.Fatalf("write junk: %v", err)
	}
}

// readStatusLine reads one response line, returning "" if the peer closed
// without answering.
func readStatusLine(c net.Conn) string {
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	n, _ := c.Read(buf)
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

// TestOversizedRequestLineDoesNotWedgeServer feeds a request line with no
// newline and then checks the gateway still serves a normal client.
func TestOversizedRequestLineDoesNotWedgeServer(t *testing.T) {
	relayUp := testutil.StartFakeHTTPUpstream(t, "ok", testutil.StartEchoServer(t, "marker-A"), "", "")
	cfg, fr := testServerConfig(t, relayUp.Addr)
	gw := startServer(t, cfg, fr)

	c, err := net.DialTimeout("tcp", gw, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	start := time.Now()
	// Two full reader buffers with no newline: enough to trip the request-line
	// cap, and fully consumed by the gateway before it answers.
	writeJunk(t, c, 2*8192)
	resp := readStatusLine(c)
	c.Close()
	elapsed := time.Since(start)
	if !strings.Contains(resp, "431") {
		t.Fatalf("response = %q after %v, want 431 for an unterminated request line", resp, elapsed)
	}
	if elapsed > 1*time.Second {
		t.Fatalf("server took %v to refuse an unterminated request line", elapsed)
	}

	st, body := connectThrough(t, gw, "example.com:443", basicAuth("pc-01", "secret-a"), "hello\n")
	if !strings.Contains(st, "200") || !strings.Contains(body, "marker-A") {
		t.Fatalf("server unhealthy after abusive request: status %q body %q", st, body)
	}
}

// TestOversizedHeaderDoesNotWedgeServer is the same check for a header line
// after a well-formed request line.
func TestOversizedHeaderDoesNotWedgeServer(t *testing.T) {
	relayUp := testutil.StartFakeHTTPUpstream(t, "ok", testutil.StartEchoServer(t, "marker-A"), "", "")
	cfg, fr := testServerConfig(t, relayUp.Addr)
	gw := startServer(t, cfg, fr)

	c, err := net.DialTimeout("tcp", gw, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	start := time.Now()
	io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nX-Pad: ")
	// Five full reader buffers with no newline trips the header cap.
	writeJunk(t, c, 5*8192)
	resp := readStatusLine(c)
	c.Close()
	elapsed := time.Since(start)
	if !strings.Contains(resp, "431") {
		t.Fatalf("response = %q after %v, want 431 for an unterminated header", resp, elapsed)
	}
	if elapsed > 1*time.Second {
		t.Fatalf("server took %v to refuse an unterminated header", elapsed)
	}

	st, body := connectThrough(t, gw, "example.com:443", basicAuth("pc-01", "secret-a"), "hello\n")
	if !strings.Contains(st, "200") || !strings.Contains(body, "marker-A") {
		t.Fatalf("server unhealthy after abusive header: status %q body %q", st, body)
	}
}

func TestGatewayIPv6TargetAllowed(t *testing.T) {
	relayUp := testutil.StartFakeHTTPUpstream(t, "ok", testutil.StartEchoServer(t, "marker-v6"), "", "")
	cfg, fr := testServerConfig(t, relayUp.Addr)
	cfg.Allowlist = append(cfg.Allowlist, "v6.example.com")
	fr.IPs["v6.example.com"] = []net.IP{net.ParseIP("2606:4700:4700::1111")}
	gw := startServer(t, cfg, fr)
	st, body := connectThrough(t, gw, "v6.example.com:443", basicAuth("pc-01", "secret-a"), "hello\n")
	if !strings.Contains(st, "200") {
		t.Fatalf("status %q", st)
	}
	if !strings.Contains(body, "marker-v6") {
		t.Fatalf("body %q", body)
	}
	dests := relayUp.Destinations()
	if len(dests) == 0 || dests[0] != "[2606:4700:4700::1111]:443" {
		t.Fatalf("upstream CONNECT target = %v, want bracketed IPv6", dests)
	}
}

func newDrainServer(t *testing.T, cfg *config.Config, fr *testutil.FakeResolver) (*Server, string, chan error) {
	t.Helper()
	s, err := NewWithDeps(cfg, access.NewPolicy(cfg, fr), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.DrainGrace = 300 * time.Millisecond
	s.DrainHard = 2 * time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- s.ServeListener(ln) }()
	time.Sleep(80 * time.Millisecond)
	return s, ln.Addr().String(), errCh
}

func TestShutdownDrainsWhenIdle(t *testing.T) {
	fwd := testutil.StartFakeHTTPUpstream(t, "ok", "", "", "")
	cfg, fr := testServerConfig(t, fwd.Addr)
	s, _, errCh := newDrainServer(t, cfg, fr)
	start := time.Now()
	s.Shutdown()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("shutdown returned %v", err)
		}
		if elapsed := time.Since(start); elapsed > 1*time.Second {
			t.Fatalf("idle shutdown took %v, expected an immediate drain", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("ServeListener did not return after Shutdown")
	}
}

// TestShutdownForceClosesIdleTunnel is the regression for a stop that hung: an
// open but idle tunnel used to hold the upstream leg until tunnel_idle_ms, so
// the drain could not finish within its grace period.
func TestShutdownForceClosesIdleTunnel(t *testing.T) {
	echo := testutil.StartEchoServer(t, "marker-A")
	fwd := testutil.StartFakeHTTPUpstream(t, "ok", echo, "", "")
	cfg, fr := testServerConfig(t, fwd.Addr)
	cfg.Timeouts.TunnelIdleMs = 60000
	s, gw, errCh := newDrainServer(t, cfg, fr)

	c, err := net.DialTimeout("tcp", gw, 3*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: "+basicAuth("pc-01", "secret-a")+"\r\n\r\n")
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	// Tunnel is up and now goes quiet in both directions.
	c.SetDeadline(time.Time{})
	if got := s.ActiveCount(); got != 1 {
		t.Fatalf("active tunnels = %d, want 1", got)
	}

	start := time.Now()
	s.Shutdown()
	select {
	case err := <-errCh:
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("shutdown returned %v after %v", err, elapsed)
		}
		if elapsed > 3*time.Second {
			t.Fatalf("shutdown took %v with an idle tunnel open", elapsed)
		}
		if elapsed < 250*time.Millisecond {
			t.Fatalf("shutdown took %v, grace period was skipped", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("ServeListener hung on an idle tunnel")
	}
	if got := s.ActiveCount(); got != 0 {
		t.Fatalf("active tunnels after drain = %d, want 0", got)
	}
}

// TestShutdownBeforeServeListener covers Shutdown winning the race against
// listener registration: the accept loop must not be left running.
func TestShutdownBeforeServeListener(t *testing.T) {
	fwd := testutil.StartFakeHTTPUpstream(t, "ok", "", "", "")
	cfg, fr := testServerConfig(t, fwd.Addr)
	s, err := NewWithDeps(cfg, access.NewPolicy(cfg, fr), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.DrainGrace = 300 * time.Millisecond
	s.DrainHard = 2 * time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	s.Shutdown()
	errCh := make(chan error, 1)
	go func() { errCh <- s.ServeListener(ln) }()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServeListener returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("ServeListener kept accepting after an early Shutdown")
	}
}

// TestClientEarlyDataForwardedOnce is the client-side mirror of the upstream
// early-data bug: payload pipelined into the same packet as the CONNECT head
// must reach the upstream exactly once.
func TestClientEarlyDataForwardedOnce(t *testing.T) {
	echo := testutil.StartEchoServer(t, "MARK")
	fwd := testutil.StartFakeHTTPUpstream(t, "ok", echo, "", "")
	cfg, fr := testServerConfig(t, fwd.Addr)
	gw := startServer(t, cfg, fr)

	c, err := net.DialTimeout("tcp", gw, 3*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: "+basicAuth("pc-01", "secret-a")+"\r\n\r\nEARLY-PAYLOAD\n")
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	var sb strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
		n, err := br.Read(buf)
		if n > 0 {
			sb.WriteString(string(buf[:n]))
		}
		if strings.Contains(sb.String(), "EARLY-PAYLOAD") {
			break
		}
		if err != nil {
			break
		}
	}
	got := sb.String()
	if n := strings.Count(got, "EARLY-PAYLOAD"); n != 1 {
		t.Fatalf("payload echoed %d times, want exactly 1: %q", n, got)
	}
}

// ctxAwareDialer holds the dial until release is closed, but gives up as soon as
// the context is cancelled, the way every real dialer behaves.
type ctxAwareDialer struct {
	started chan struct{}
	release chan struct{}
	target  string
	once    sync.Once
}

func (d *ctxAwareDialer) Dial(ctx context.Context, _ access.Target) (net.Conn, []byte, error) {
	d.once.Do(func() { close(d.started) })
	select {
	case <-d.release:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	c, err := net.Dial("tcp", d.target)
	return c, nil, err
}

// TestShutdownDuringUpstreamDial covers a SIGTERM that lands while a handler is
// still dialling: the dial has to be cancelled, otherwise the handler outlives
// DrainHard and shutdown reports a spurious failure.
func TestShutdownDuringUpstreamDial(t *testing.T) {
	echo := testutil.StartEchoServer(t, "MARK")
	cfg, fr := testServerConfig(t, "127.0.0.1:1")
	cfg.Timeouts.TunnelIdleMs = 60000
	d := &ctxAwareDialer{started: make(chan struct{}), release: make(chan struct{}), target: echo}
	s, err := NewWithDeps(cfg, access.NewPolicy(cfg, fr), d)
	if err != nil {
		t.Fatal(err)
	}
	s.DrainGrace = 100 * time.Millisecond
	s.DrainHard = 500 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer close(d.release)
	errCh := make(chan error, 1)
	go func() { errCh <- s.ServeListener(ln) }()
	time.Sleep(80 * time.Millisecond)

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer c.Close()
	io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: "+basicAuth("pc-01", "secret-a")+"\r\n\r\n")
	select {
	case <-d.started:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream dial never started")
	}

	start := time.Now()
	s.Shutdown()
	select {
	case err := <-errCh:
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("shutdown returned %v after %v; the in-flight dial was not cancelled", err, elapsed)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("shutdown took %v with a dial in flight", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeListener hung on an in-flight dial")
	}
}

// TestPendingHandshakesAreCapped checks that connections which never finish a
// handshake cannot pin a header buffer each.
func TestPendingHandshakesAreCapped(t *testing.T) {
	fwd := testutil.StartFakeHTTPUpstream(t, "ok", testutil.StartEchoServer(t, "marker-A"), "", "")
	cfg, fr := testServerConfig(t, fwd.Addr)
	cfg.Limits.MaxPendingHandshakes = 3
	gw := startServer(t, cfg, fr)

	// Occupy every pending slot with peers that connect and then say nothing.
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < 3; i++ {
		c, err := net.DialTimeout("tcp", gw, 3*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		held = append(held, c)
	}
	time.Sleep(200 * time.Millisecond)

	c, err := net.DialTimeout("tcp", gw, 3*time.Second)
	if err != nil {
		t.Fatalf("dial overflow: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	// The overload check runs immediately after Accept, before the gateway
	// reads a request. Keep this peer silent: closing a socket with unread
	// client data can turn the response into a TCP reset on Windows.
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "503") {
		t.Fatalf("status = %q, want 503 once the pending cap is reached", status)
	}
}

// TestDuplicateProxyAuthorizationRejected: two credentials in one request is
// ambiguous, so it must be refused rather than last-one-wins.
func TestDuplicateProxyAuthorizationRejected(t *testing.T) {
	fwd := testutil.StartFakeHTTPUpstream(t, "ok", testutil.StartEchoServer(t, "marker-A"), "", "")
	cfg, fr := testServerConfig(t, fwd.Addr)
	gw := startServer(t, cfg, fr)

	c, err := net.DialTimeout("tcp", gw, 3*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\n"+
		"Proxy-Authorization: "+basicAuth("pc-01", "wrong")+"\r\n"+
		"Proxy-Authorization: "+basicAuth("pc-01", "secret-a")+"\r\n\r\n")
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "400") {
		t.Fatalf("status = %q, want 400 for a duplicated Proxy-Authorization", status)
	}
}

// TestRepeatedShutdownDoesNotLeak starts and stops the server many times and
// checks that goroutines wind down each round.
func TestRepeatedShutdownDoesNotLeak(t *testing.T) {
	echo := testutil.StartEchoServer(t, "marker-A")
	fwd := testutil.StartFakeHTTPUpstream(t, "ok", echo, "", "")

	settle := func() int {
		var n int
		for i := 0; i < 50; i++ {
			runtime.GC()
			n = runtime.NumGoroutine()
			time.Sleep(20 * time.Millisecond)
			if runtime.NumGoroutine() <= n {
				break
			}
		}
		return runtime.NumGoroutine()
	}

	cfg, fr := testServerConfig(t, fwd.Addr)
	// One warm-up round so lazily created goroutines are not counted as a leak.
	runRound(t, cfg, fr)
	before := settle()

	const rounds = 15
	for i := 0; i < rounds; i++ {
		runRound(t, cfg, fr)
	}
	after := settle()

	if after > before+5 {
		t.Fatalf("goroutines grew from %d to %d over %d shutdown rounds", before, after, rounds)
	}
}

// runRound brings a server up, pushes one tunnel through it, and shuts it down.
func runRound(t *testing.T, cfg *config.Config, fr *testutil.FakeResolver) {
	t.Helper()
	s, err := NewWithDeps(cfg, access.NewPolicy(cfg, fr), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.DrainGrace = 50 * time.Millisecond
	s.DrainHard = 2 * time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- s.ServeListener(ln) }()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: "+basicAuth("pc-01", "secret-a")+"\r\n\r\n")
	br := bufio.NewReader(c)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("read status: %v", err)
	}
	c.Close()

	s.Shutdown()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("shutdown returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeListener did not return")
	}
}
