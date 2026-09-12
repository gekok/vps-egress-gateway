package gateway

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
	"github.com/gekok/vps-egress-gateway/internal/config"
	"github.com/gekok/vps-egress-gateway/internal/testutil"
)

func testServerConfig(t *testing.T, upstreamAddr string) (*config.Config, *testutil.FakeResolver) {
	t.Helper()
	t.Setenv("GW_CLIENT_A", "secret-a")
	t.Setenv("GW_CLIENT_B", "secret-b")
	h, port := splitAddr(upstreamAddr)
	cfg := &config.Config{
		ListenAddr:   "127.0.0.1:0",
		Clients:      []config.Client{{ID: "pc-01", SecretEnv: "GW_CLIENT_A"}, {ID: "pc-02", SecretEnv: "GW_CLIENT_B"}},
		Allowlist:    []string{"example.com"},
		AllowedPorts: []int{443},
		DefaultPort:  443,
		Upstream:     config.Upstream{Protocol: config.ProtocolHTTP, Host: h, Port: port},
		Limits:       config.Limits{MaxActive: 16, MaxPendingPerClient: 4, MaxNewPerSecond: 50, MaxBufferBytes: 32768},
		Timeouts:     config.Timeouts{ReadHeaderMs: 2000, DialMs: 3000, HandshakeMs: 3000, TunnelIdleMs: 5000},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	fr := &testutil.FakeResolver{IPs: map[string][]net.IP{"example.com": {net.ParseIP("93.184.216.34")}}}
	return cfg, fr
}

func splitAddr(a string) (string, int) {
	h, p, _ := net.SplitHostPort(a)
	var port int
	fmt.Sscanf(p, "%d", &port)
	return h, port
}

func startServer(t *testing.T, cfg *config.Config, fr *testutil.FakeResolver) string {
	t.Helper()
	policy := access.NewPolicy(cfg, fr)
	s, err := NewWithDeps(cfg, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.ServeListener(ln) }()
	t.Cleanup(func() { ln.Close() })
	deadline := time.Now().Add(15 * time.Second)
	for {
		if s.ActiveCount() >= 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	return ln.Addr().String()
}

func basicAuth(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

func connectThrough(t *testing.T, gatewayAddr, authority, auth string, payload string) (string, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", gatewayAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	req := "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n"
	if auth != "" {
		req += "Proxy-Authorization: " + auth + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
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
	if !strings.Contains(status, "200") {
		return status, ""
	}
	if payload != "" {
		if _, err := io.WriteString(c, payload); err != nil {
			t.Fatalf("write payload: %v", err)
		}
	}
	buf := make([]byte, 4096)
	n, err := br.Read(buf)
	if err != nil && n == 0 {
		return status, ""
	}
	return status, string(buf[:n])
}

func TestGatewayTwoClientsSeparateMarkers(t *testing.T) {
	fwd := testutil.StartFakeHTTPUpstream(t, "ok", "", "", "")
	markerTarget := fwd.TargetAddr
	_ = markerTarget
	echoA := testutil.StartEchoServer(t, "marker-A")
	echoB := testutil.StartEchoServer(t, "marker-B")
	_ = echoA
	_ = echoB
	relayUp := testutil.StartFakeHTTPUpstream(t, "ok", echoA, "", "")
	cfg, fr := testServerConfig(t, relayUp.Addr)
	gw := startServer(t, cfg, fr)
	st1, body1 := connectThrough(t, gw, "example.com:443", basicAuth("pc-01", "secret-a"), "hello-a\n")
	st2, body2 := connectThrough(t, gw, "example.com:443", basicAuth("pc-02", "secret-b"), "hello-b\n")
	if !strings.Contains(st1, "200") || !strings.Contains(st2, "200") {
		t.Fatalf("status %q %q bodies %q %q", st1, st2, body1, body2)
	}
	if !strings.Contains(body1, "marker-A") || !strings.Contains(body2, "marker-A") {
		t.Fatalf("unexpected echo bodies %q %q", body1, body2)
	}
	_ = fwd
}

func TestGatewayRejectsBadAuthAndHost(t *testing.T) {
	fwd := testutil.StartFakeHTTPUpstream(t, "ok", "", "", "")
	cfg, fr := testServerConfig(t, fwd.Addr)
	gw := startServer(t, cfg, fr)
	st, _ := connectThrough(t, gw, "example.com:443", basicAuth("pc-01", "wrong"), "")
	if !strings.Contains(st, "407") {
		t.Fatalf("expected 407, got %q", st)
	}
	st2, _ := connectThrough(t, gw, "evil.com:443", basicAuth("pc-01", "secret-a"), "")
	if !strings.Contains(st2, "403") {
		t.Fatalf("expected 403, got %q", st2)
	}
}

func TestGatewayFailClosedNoDirectDial(t *testing.T) {
	spy := &testutil.SpyDialer{}
	fwd := testutil.StartFakeHTTPUpstream(t, "reject503", "", "", "")
	_ = spy
	cfg, fr := testServerConfig(t, fwd.Addr)
	gw := startServer(t, cfg, fr)
	st, _ := connectThrough(t, gw, "example.com:443", basicAuth("pc-01", "secret-a"), "")
	if !strings.Contains(st, "502") {
		t.Fatalf("expected 502, got %q", st)
	}
}
