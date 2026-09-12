package integration

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
	"github.com/gekok/vps-egress-gateway/internal/config"
	"github.com/gekok/vps-egress-gateway/internal/gateway"
	"github.com/gekok/vps-egress-gateway/internal/testutil"
)

func basic(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

func startGateway(t *testing.T, upstreamAddr string) string {
	t.Helper()
	t.Setenv("REG_A", "reg-secret-a")
	t.Setenv("REG_B", "reg-secret-b")
	h, port := "127.0.0.1", 0
	hh, pp, _ := net.SplitHostPort(upstreamAddr)
	h = hh
	for _, c := range pp {
		port = port*10 + int(c-'0')
	}
	cfg := &config.Config{
		ListenAddr:   "127.0.0.1:0",
		Clients:      []config.Client{{ID: "pc-01", SecretEnv: "REG_A"}, {ID: "pc-02", SecretEnv: "REG_B"}},
		Allowlist:    []string{"example.com"},
		AllowedPorts: []int{443},
		DefaultPort:  443,
		Upstream:     config.Upstream{Protocol: config.ProtocolHTTP, Host: h, Port: port},
		Limits:       config.Limits{MaxActive: 32, MaxPendingPerClient: 8, MaxNewPerSecond: 100, MaxBufferBytes: 32768},
		Timeouts:     config.Timeouts{ReadHeaderMs: 2000, DialMs: 3000, HandshakeMs: 3000, TunnelIdleMs: 4000},
	}
	fr := &testutil.FakeResolver{IPs: map[string][]net.IP{"example.com": {net.ParseIP("93.184.216.34")}}}
	s, err := gateway.NewWithDeps(cfg, access.NewPolicy(cfg, fr), nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.ServeListener(ln) }()
	t.Cleanup(func() { ln.Close() })
	time.Sleep(80 * time.Millisecond)
	return ln.Addr().String()
}

func roundTrip(t *testing.T, gw, auth, marker string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", gw, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: "+auth+"\r\n\r\n")
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status %q", status)
	}
	io.WriteString(c, marker+"\n")
	var sb strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := br.Read(buf)
		if n > 0 {
			sb.WriteString(string(buf[:n]))
			if strings.Contains(sb.String(), marker) {
				break
			}
		}
	}
	return sb.String()
}

func TestConcurrentNoCrossTalk(t *testing.T) {
	echo := testutil.StartEchoServer(t, "shared-marker")
	fwd := testutil.StartFakeHTTPUpstream(t, "ok", echo, "", "")
	gw := startGateway(t, fwd.Addr)
	var wg sync.WaitGroup
	results := make([]string, 4)
	auths := []string{basic("pc-01", "reg-secret-a"), basic("pc-02", "reg-secret-b"), basic("pc-01", "reg-secret-a"), basic("pc-02", "reg-secret-b")}
	markers := []string{"c1-m1", "c2-m1", "c1-m2", "c2-m2"}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = roundTrip(t, gw, auths[i], markers[i])
		}(i)
	}
	wg.Wait()
	for i, m := range markers {
		if !strings.Contains(results[i], m) {
			t.Fatalf("client %d missing marker %q in %q", i, m, results[i])
		}
	}
}

func TestAbruptDisconnectCleansUp(t *testing.T) {
	echo := testutil.StartEchoServer(t, "x")
	fwd := testutil.StartFakeHTTPUpstream(t, "ok", echo, "", "")
	gw := startGateway(t, fwd.Addr)
	for i := 0; i < 5; i++ {
		c, _ := net.DialTimeout("tcp", gw, 2*time.Second)
		io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\nProxy-Authorization: "+basic("pc-01", "reg-secret-a")+"\r\n\r\n")
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}
	time.Sleep(500 * time.Millisecond)
}
