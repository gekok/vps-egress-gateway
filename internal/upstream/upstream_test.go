package upstream

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
	"github.com/gekok/vps-egress-gateway/internal/config"
	"github.com/gekok/vps-egress-gateway/internal/testutil"
)

func splitHostPort(a string) (string, int) {
	h, p, _ := net.SplitHostPort(a)
	var port int
	for _, c := range p {
		port = port*10 + int(c-'0')
	}
	return h, port
}

func publicTarget() access.Target {
	return access.Target{Hostname: "example.com", Port: 443, PinnedIP: net.ParseIP("93.184.216.34")}
}

func cfgHTTP(addr string) *config.Config {
	h, p := splitHostPort(addr)
	return &config.Config{
		Upstream: config.Upstream{Protocol: config.ProtocolHTTP, Host: h, Port: p},
		Timeouts: config.Timeouts{ReadHeaderMs: 2000, DialMs: 3000, HandshakeMs: 3000, TunnelIdleMs: 10000},
	}
}

func TestHTTPOK(t *testing.T) {
	f := testutil.StartFakeHTTPUpstream(t, "ok", "", "proxyuser", "proxypass")
	t.Setenv("TEST_UP_USER", "proxyuser")
	t.Setenv("TEST_UP_PASS", "proxypass")
	h, p := splitHostPort(f.Addr)
	cfg := &config.Config{
		Upstream: config.Upstream{Protocol: config.ProtocolHTTP, Host: h, Port: p, UsernameEnv: "TEST_UP_USER", PasswordEnv: "TEST_UP_PASS"},
		Timeouts: config.Timeouts{ReadHeaderMs: 2000, DialMs: 3000, HandshakeMs: 3000, TunnelIdleMs: 10000},
	}
	spy := &testutil.SpyDialer{}
	d, err := NewDialerWithNet(cfg, spy.DialContext)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := d.Dial(ctx, publicTarget())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	addrs := spy.Addresses()
	if len(addrs) != 1 || addrs[0] != f.Addr {
		t.Fatalf("expected single upstream dial, got %v", addrs)
	}
}

func TestHTTPAuthReject(t *testing.T) {
	f := testutil.StartFakeHTTPUpstream(t, "ok", "", "proxyuser", "proxypass")
	t.Setenv("TEST_UP_USER", "proxyuser")
	t.Setenv("TEST_UP_PASS", "wrong")
	h, p := splitHostPort(f.Addr)
	cfg := &config.Config{
		Upstream: config.Upstream{Protocol: config.ProtocolHTTP, Host: h, Port: p, UsernameEnv: "TEST_UP_USER", PasswordEnv: "TEST_UP_PASS"},
		Timeouts: config.Timeouts{ReadHeaderMs: 2000, DialMs: 3000, HandshakeMs: 3000, TunnelIdleMs: 10000},
	}
	d, _ := NewDialerWithNet(cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := d.Dial(ctx, publicTarget()); err == nil {
		t.Fatalf("expected auth rejection")
	}
}

func TestHTTP503MalformedOversized(t *testing.T) {
	for _, mode := range []string{"reject503", "malformed", "oversized"} {
		f := testutil.StartFakeHTTPUpstream(t, mode, "", "", "")
		d, _ := NewDialerWithNet(cfgHTTP(f.Addr), nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _, err := d.Dial(ctx, publicTarget())
		cancel()
		if err == nil {
			t.Fatalf("mode %s: expected error", mode)
		}
	}
}

func TestHTTPBufferedPreserved(t *testing.T) {
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
		t.Fatalf("expected buffered prefix, got %q", string(prefix))
	}
}

func TestHTTPSValidCAEndToEnd(t *testing.T) {
	echo := testutil.StartEchoServer(t, "https-marker")
	fwd, caPEM := testutil.StartFakeHTTPSUpstream(t, "ok", echo, "", "")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	h, p := splitHostPort(fwd.Addr)
	cfg := &config.Config{
		Upstream: config.Upstream{Protocol: config.ProtocolHTTPS, Host: h, Port: p, CAFile: caFile, ServerName: "127.0.0.1"},
		Timeouts: config.Timeouts{ReadHeaderMs: 2000, DialMs: 3000, HandshakeMs: 5000, TunnelIdleMs: 10000},
	}
	d, err := NewDialerWithNet(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := d.Dial(ctx, publicTarget())
	if err != nil {
		t.Fatalf("https dial: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("read marker: %v n=%d", err, n)
	}
	if !strings.Contains(string(buf[:n]), "https-marker") {
		t.Fatalf("unexpected marker %q", string(buf[:n]))
	}
}

func TestHTTPSBadCARejected(t *testing.T) {
	echo := testutil.StartEchoServer(t, "tls-marker")
	fwd, _ := testutil.StartFakeHTTPSUpstream(t, "ok", echo, "", "")
	badCA := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(badCA, []byte("not-a-cert"), 0600)
	h, p := splitHostPort(fwd.Addr)
	cfg := &config.Config{
		Upstream: config.Upstream{Protocol: config.ProtocolHTTPS, Host: h, Port: p, CAFile: badCA, ServerName: "127.0.0.1"},
		Timeouts: config.Timeouts{ReadHeaderMs: 2000, DialMs: 3000, HandshakeMs: 5000, TunnelIdleMs: 10000},
	}
	d, _ := NewDialerWithNet(cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, _, err := d.Dial(ctx, publicTarget()); err == nil {
		t.Fatalf("expected CA rejection")
	}
}

func TestSOCKS5AuthOK(t *testing.T) {
	echo := testutil.StartEchoServer(t, "socks-marker")
	s5 := testutil.StartFakeSOCKS5(t, "s5user", "s5pass", echo)
	t.Setenv("TEST_S5_USER", "s5user")
	t.Setenv("TEST_S5_PASS", "s5pass")
	h, p := splitHostPort(s5.Addr)
	cfg := &config.Config{
		Upstream: config.Upstream{Protocol: config.ProtocolSOCKS5, Host: h, Port: p, UsernameEnv: "TEST_S5_USER", PasswordEnv: "TEST_S5_PASS"},
		Timeouts: config.Timeouts{ReadHeaderMs: 2000, DialMs: 3000, HandshakeMs: 5000, TunnelIdleMs: 10000},
	}
	d, err := NewDialerWithNet(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, _, err := d.Dial(ctx, access.Target{Hostname: "example.com", Port: 443, PinnedIP: net.ParseIP("93.184.216.34")})
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("read marker: %v", err)
	}
}

func TestSOCKS5AuthFail(t *testing.T) {
	echo := testutil.StartEchoServer(t, "socks-marker")
	s5 := testutil.StartFakeSOCKS5(t, "s5user", "s5pass", echo)
	t.Setenv("TEST_S5_USER", "s5user")
	t.Setenv("TEST_S5_PASS", "wrong")
	h, p := splitHostPort(s5.Addr)
	cfg := &config.Config{
		Upstream: config.Upstream{Protocol: config.ProtocolSOCKS5, Host: h, Port: p, UsernameEnv: "TEST_S5_USER", PasswordEnv: "TEST_S5_PASS"},
		Timeouts: config.Timeouts{ReadHeaderMs: 2000, DialMs: 3000, HandshakeMs: 5000, TunnelIdleMs: 10000},
	}
	d, _ := NewDialerWithNet(cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, _, err := d.Dial(ctx, publicTarget()); err == nil {
		t.Fatalf("expected socks auth failure")
	}
}
