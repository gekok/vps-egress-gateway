package upstream

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
	"github.com/gekok/vps-egress-gateway/internal/config"
	"github.com/gekok/vps-egress-gateway/internal/testutil"
)

// TestHTTPEarlyDataDeliveredOnce guards the corruption bug where bytes the
// upstream packed in with its CONNECT response were returned as the buffered
// prefix and then handed out again on every read of the tunnel.
func TestHTTPEarlyDataDeliveredOnce(t *testing.T) {
	f := testutil.StartFakeHTTPUpstream(t, "ok-buffered", "", "", "")
	d, _ := NewDialerWithNet(cfgHTTP(f.Addr), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, prefix, err := d.Dial(ctx, publicTarget())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if !strings.Contains(string(prefix), "HELLO-BUFFERED") {
		t.Fatalf("expected early data in prefix, got %q", string(prefix))
	}
	if _, err := io.WriteString(conn, "PING\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("read echo: %v n=%d", err, n)
	}
	got := string(buf[:n])
	if strings.Contains(got, "HELLO-BUFFERED") {
		t.Fatalf("early data replayed on the tunnel: %q", got)
	}
	if !strings.Contains(got, "PING") {
		t.Fatalf("expected echoed payload, got %q", got)
	}
}

// TestHTTPEarlyDataNotLost is the other half: draining the reader must not drop
// the bytes, they still have to reach the caller exactly once.
func TestHTTPEarlyDataNotLost(t *testing.T) {
	f := testutil.StartFakeHTTPUpstream(t, "ok-buffered", "", "", "")
	d, _ := NewDialerWithNet(cfgHTTP(f.Addr), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, prefix, err := d.Dial(ctx, publicTarget())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if string(prefix) != "HELLO-BUFFERED:" {
		t.Fatalf("prefix = %q, want %q", string(prefix), "HELLO-BUFFERED:")
	}
}

type endlessReader struct{ b byte }

func (e endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = e.b
	}
	return len(p), nil
}

func TestReadLineLimitedBoundsUnterminatedLine(t *testing.T) {
	br := bufio.NewReaderSize(endlessReader{b: 'A'}, 4096)
	done := make(chan error, 1)
	go func() {
		_, err := readLineLimited(br, 32768)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected error on unterminated line")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("readLineLimited did not stop on an endless line")
	}
}

func TestReadLineLimitedAcceptsLineAtLimit(t *testing.T) {
	line := strings.Repeat("B", 99) + "\n"
	br := bufio.NewReaderSize(strings.NewReader(line), 16)
	got, err := readLineLimited(br, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != line {
		t.Fatalf("got %d bytes, want %d", len(got), len(line))
	}
}

// TestHTTPUnterminatedUpstreamHeader covers an upstream that answers CONNECT
// with a stream that never contains a newline.
func TestHTTPUnterminatedUpstreamHeader(t *testing.T) {
	addr := testutil.StartUnterminatedHeader(t)
	cfg := cfgHTTP(addr)
	cfg.Timeouts.HandshakeMs = 1500
	d, _ := NewDialerWithNet(cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	conn, _, err := d.Dial(ctx, publicTarget())
	if err == nil {
		conn.Close()
		t.Fatalf("expected error from unterminated upstream header")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v to reject an unterminated header", elapsed)
	}
}

// TestHTTPIPv6TargetIsBracketed checks the CONNECT request line stays parseable
// when the pinned address is IPv6.
func TestHTTPIPv6TargetIsBracketed(t *testing.T) {
	f := testutil.StartFakeHTTPUpstream(t, "ok", "", "", "")
	d, _ := NewDialerWithNet(cfgHTTP(f.Addr), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tgt := access.Target{Hostname: "v6.example.com", Port: 443, PinnedIP: net.ParseIP("2606:4700:4700::1111")}
	conn, _, err := d.Dial(ctx, tgt)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	dests := f.Destinations()
	if len(dests) != 1 {
		t.Fatalf("expected one CONNECT, got %v", dests)
	}
	if dests[0] != "[2606:4700:4700::1111]:443" {
		t.Fatalf("CONNECT target = %q, want bracketed IPv6 authority", dests[0])
	}
}

// TestSOCKS5SilentUpstreamDoesNotHang covers an upstream that completes the TCP
// handshake and then never answers the SOCKS5 greeting. proxy.Dialer.Dial runs
// that exchange under context.Background(), so this used to block forever.
func TestSOCKS5SilentUpstreamDoesNotHang(t *testing.T) {
	addr := testutil.StartSilentTCP(t)
	h, p := splitHostPort(addr)
	cfg := &config.Config{
		Upstream: config.Upstream{Protocol: config.ProtocolSOCKS5, Host: h, Port: p},
		Timeouts: config.Timeouts{ReadHeaderMs: 2000, DialMs: 3000, HandshakeMs: 800, TunnelIdleMs: 10000},
	}
	d, err := NewDialerWithNet(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		conn, _, err := d.Dial(context.Background(), publicTarget())
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected socks5 handshake timeout")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("socks5 handshake took %v to give up", elapsed)
		}
	case <-time.After(8 * time.Second):
		t.Fatalf("socks5 handshake hung on a silent upstream")
	}
}

// TestSOCKS5UsesInjectedDialer proves every socket still goes to the configured
// upstream address and nothing dials the destination directly.
func TestSOCKS5UsesInjectedDialer(t *testing.T) {
	echo := testutil.StartEchoServer(t, "socks-marker")
	s5 := testutil.StartFakeSOCKS5(t, "", "", echo)
	h, p := splitHostPort(s5.Addr)
	cfg := &config.Config{
		Upstream: config.Upstream{Protocol: config.ProtocolSOCKS5, Host: h, Port: p},
		Timeouts: config.Timeouts{ReadHeaderMs: 2000, DialMs: 3000, HandshakeMs: 5000, TunnelIdleMs: 10000},
	}
	spy := &testutil.SpyDialer{}
	d, err := NewDialerWithNet(cfg, spy.DialContext)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, _, err := d.Dial(ctx, publicTarget())
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	defer conn.Close()
	addrs := spy.Addresses()
	if len(addrs) != 1 || addrs[0] != s5.Addr {
		t.Fatalf("expected a single dial to the upstream, got %v", addrs)
	}
}

// TestIPv6UpstreamHostIsBracketed guards the upstream authority itself: a bare
// Sprintf produced "2606:4700:4700::1111:3128", which no dialer can parse.
func TestIPv6UpstreamHostIsBracketed(t *testing.T) {
	for _, host := range []string{"2606:4700:4700::1111", "::1"} {
		cfg := &config.Config{
			Upstream: config.Upstream{Protocol: config.ProtocolHTTP, Host: host, Port: 3128},
			Timeouts: config.Timeouts{ReadHeaderMs: 1000, DialMs: 1000, HandshakeMs: 1000, TunnelIdleMs: 1000},
		}
		d, err := NewDialerWithNet(cfg, nil)
		if err != nil {
			t.Fatalf("new dialer for %s: %v", host, err)
		}
		got := d.(*httpDialer).upstreamAddr
		want := "[" + host + "]:3128"
		if got != want {
			t.Fatalf("upstream addr = %q, want %q", got, want)
		}
		if _, _, err := net.SplitHostPort(got); err != nil {
			t.Fatalf("upstream addr %q is not a valid authority: %v", got, err)
		}
	}
}
