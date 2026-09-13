package integration

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
	"github.com/gekok/vps-egress-gateway/internal/config"
	"github.com/gekok/vps-egress-gateway/internal/gateway"
	"github.com/gekok/vps-egress-gateway/internal/testutil"
	"github.com/gekok/vps-egress-gateway/internal/upstream"
	"golang.org/x/net/websocket"
)

type testGateway struct {
	s               *gateway.Server
	addr, proxyAddr string
	spy             *testutil.SpyDialer
	httpProxy       *testutil.FakeUpstream
}

func newGateway(t *testing.T, protocol, target string) testGateway {
	t.Helper()
	t.Setenv("REG_A", "reg-secret-a")
	t.Setenv("REG_B", "reg-secret-b")
	t.Setenv("REG_UP_USER", "up-user")
	t.Setenv("REG_UP_PASS", "up-pass")
	g := testGateway{spy: &testutil.SpyDialer{}}
	u := config.Upstream{Protocol: protocol, UsernameEnv: "REG_UP_USER", PasswordEnv: "REG_UP_PASS"}
	switch protocol {
	case config.ProtocolHTTP:
		g.httpProxy = testutil.StartFakeHTTPUpstream(t, "ok", target, "up-user", "up-pass")
		g.proxyAddr = g.httpProxy.Addr
	case config.ProtocolHTTPS:
		var ca []byte
		g.httpProxy, ca = testutil.StartFakeHTTPSUpstream(t, "ok", target, "up-user", "up-pass")
		g.proxyAddr = g.httpProxy.Addr
		u.CAFile = filepath.Join(t.TempDir(), "proxy-ca.pem")
		if err := os.WriteFile(u.CAFile, ca, 0600); err != nil {
			t.Fatal(err)
		}
	case config.ProtocolSOCKS5:
		g.proxyAddr = testutil.StartFakeSOCKS5(t, "up-user", "up-pass", target).Addr
	}
	h, p, err := net.SplitHostPort(g.proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = h
	u.Port, err = strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0", Clients: []config.Client{{ID: "pc-01", SecretEnv: "REG_A"}, {ID: "pc-02", SecretEnv: "REG_B"}},
		Allowlist: []string{"example.com"}, AllowedPorts: []int{443}, DefaultPort: 443, Upstream: u,
		Limits:   config.Limits{MaxActive: 32, MaxPendingPerClient: 8, MaxNewPerSecond: 100, MaxBufferBytes: 32768},
		Timeouts: config.Timeouts{ReadHeaderMs: 2000, DialMs: 2000, HandshakeMs: 2000, TunnelIdleMs: 1500},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	d, err := upstream.NewDialerWithNet(cfg, g.spy.DialContext)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &testutil.FakeResolver{IPs: map[string][]net.IP{"example.com": {net.ParseIP("93.184.216.34")}}}
	g.s, err = gateway.NewWithDeps(cfg, access.NewPolicy(cfg, resolver), d)
	if err != nil {
		t.Fatal(err)
	}
	g.s.DrainGrace = 50 * time.Millisecond
	g.s.DrainHard = time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g.addr = ln.Addr().String()
	done := make(chan error, 1)
	go func() { done <- g.s.ServeListener(ln) }()
	t.Cleanup(func() {
		g.s.Shutdown()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("gateway shutdown hung")
		}
		if g.s.ActiveCount() != 0 || g.s.PendingCount() != 0 || g.s.ConnectionCount() != 0 {
			t.Error("gateway leaked resources")
		}
		for _, addr := range g.spy.Addresses() {
			if addr != g.proxyAddr {
				t.Errorf("direct dial attempted: %q", addr)
			}
		}
		if g.httpProxy != nil {
			for _, auth := range g.httpProxy.Authorizations() {
				if auth != basic("up-user", "up-pass") {
					t.Error("client credential forwarded upstream")
				}
			}
			for _, dest := range g.httpProxy.Destinations() {
				if dest != "93.184.216.34:443" {
					t.Errorf("target not pinned: %s", dest)
				}
			}
		}
	})
	return g
}

func openTunnel(g testGateway, id, secret string) (net.Conn, *bufio.Reader, error) {
	c, err := net.DialTimeout("tcp", g.addr, 2*time.Second)
	if err != nil {
		return nil, nil, err
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: %s\r\n\r\n", basic(id, secret)); err != nil {
		c.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		c.Close()
		return nil, nil, fmt.Errorf("CONNECT status %d", resp.StatusCode)
	}
	return c, br, nil
}

func TestTransportMatrixHalfCloseAndIsolation(t *testing.T) {
	for _, protocol := range []string{config.ProtocolHTTP, config.ProtocolHTTPS, config.ProtocolSOCKS5} {
		t.Run(protocol, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			testutil.Serve(t, ln, func(c net.Conn) {
				c.SetDeadline(time.Now().Add(5 * time.Second))
				body, err := io.ReadAll(c)
				if err == nil {
					fmt.Fprintf(c, "reply:%s", body)
				}
			})
			g := newGateway(t, protocol, ln.Addr().String())
			results := make(chan error, 4)
			for i := 0; i < 4; i++ {
				go func(i int) {
					id, secret := "pc-01", "reg-secret-a"
					if i%2 == 1 {
						id, secret = "pc-02", "reg-secret-b"
					}
					c, br, err := openTunnel(g, id, secret)
					if err != nil {
						results <- err
						return
					}
					defer c.Close()
					marker := fmt.Sprintf("client-%d", i)
					if _, err = io.WriteString(c, marker); err == nil {
						err = c.(*net.TCPConn).CloseWrite()
					}
					if err != nil {
						results <- err
						return
					}
					body, err := io.ReadAll(br)
					if err == nil && string(body) != "reply:"+marker {
						err = fmt.Errorf("cross-talk/truncation: %q", body)
					}
					results <- err
				}(i)
			}
			for i := 0; i < 4; i++ {
				if err := <-results; err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestTransportMatrixTLSStreamingAndWebSocket(t *testing.T) {
	for _, protocol := range []string{config.ProtocolHTTP, config.ProtocolHTTPS, config.ProtocolSOCKS5} {
		t.Run(protocol, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Proxy-Authorization") != "" {
					t.Error("proxy credential reached destination")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				for i := 0; i < 3; i++ {
					fmt.Fprintf(w, "data: %s-%d\n\n", r.URL.Query().Get("marker"), i)
					w.(http.Flusher).Flush()
					time.Sleep(30 * time.Millisecond)
				}
			})
			mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
				defer ws.Close()
				ws.SetDeadline(time.Now().Add(3 * time.Second))
				var msg string
				if websocket.Message.Receive(ws, &msg) == nil {
					websocket.Message.Send(ws, "reply:"+msg)
				}
			}))
			target := httptest.NewTLSServer(mux)
			defer target.Close()
			roots := x509.NewCertPool()
			roots.AddCert(target.Certificate())
			tlsCfg := &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}
			g := newGateway(t, protocol, target.Listener.Addr().String())
			proxyURL := &url.URL{Scheme: "http", Host: g.addr, User: url.UserPassword("pc-01", "reg-secret-a")}
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: tlsCfg, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			resp, err := client.Get("https://example.com/events?marker=pc-one")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(body) != "data: pc-one-0\n\ndata: pc-one-1\n\ndata: pc-one-2\n\n" {
				t.Fatalf("SSE bytes: %q %v", body, err)
			}
			c, br, err := openTunnel(g, "pc-02", "reg-secret-b")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if br.Buffered() != 0 {
				t.Fatal("unexpected data before TLS ClientHello")
			}
			secure := tls.Client(c, tlsCfg)
			if err := secure.HandshakeContext(context.Background()); err != nil {
				t.Fatal(err)
			}
			wsCfg, err := websocket.NewConfig("wss://example.com/ws", "https://example.com")
			if err != nil {
				t.Fatal(err)
			}
			ws, err := websocket.NewClient(wsCfg, secure)
			if err != nil {
				t.Fatal(err)
			}
			defer ws.Close()
			if err := websocket.Message.Send(ws, "pc-two"); err != nil {
				t.Fatal(err)
			}
			var msg string
			if err := websocket.Message.Receive(ws, &msg); err != nil || msg != "reply:pc-two" {
				t.Fatalf("WSS response %q %v", msg, err)
			}
		})
	}
}

func TestFailClosedAuthPolicyAndProxyOutage(t *testing.T) {
	for _, protocol := range []string{config.ProtocolHTTP, config.ProtocolHTTPS, config.ProtocolSOCKS5} {
		t.Run(protocol, func(t *testing.T) {
			g := newGateway(t, protocol, testutil.StartEchoServer(t, "hello"))
			if c, _, err := openTunnel(g, "pc-01", "wrong"); err == nil {
				c.Close()
				t.Fatal("wrong auth accepted")
			}
			if len(g.spy.Addresses()) != 0 {
				t.Fatal("unauthenticated peer reached upstream")
			}
			c, err := net.DialTimeout("tcp", g.addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(time.Second))
			fmt.Fprintf(c, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nProxy-Authorization: %s\r\n\r\n", basic("pc-01", "reg-secret-a"))
			status, err := bufio.NewReader(c).ReadString('\n')
			c.Close()
			if err != nil || !strings.Contains(status, "403") {
				t.Fatalf("policy: %q %v", status, err)
			}
			if len(g.spy.Addresses()) != 0 {
				t.Fatal("rejected target reached upstream")
			}
			// Fault at the socket boundary; spy records any fallback attempt.
			g.spy.DialFunc = func(context.Context, string, string) (net.Conn, error) {
				return nil, fmt.Errorf("fixture proxy unavailable")
			}
			if c, _, err := openTunnel(g, "pc-01", "reg-secret-a"); err == nil {
				c.Close()
				t.Fatal("outage accepted")
			}
			if len(g.spy.Addresses()) != 1 {
				t.Fatalf("outage attempts: %v", g.spy.Addresses())
			}
		})
	}
}
