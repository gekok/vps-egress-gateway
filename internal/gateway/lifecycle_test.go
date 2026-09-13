package gateway

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
)

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

func startManagedGateway(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.DrainGrace = 50 * time.Millisecond
	s.DrainHard = time.Second
	done := make(chan error, 1)
	go func() { done <- s.ServeListener(ln) }()
	t.Cleanup(func() {
		s.Shutdown()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("gateway did not shut down")
		}
		if s.ActiveCount() != 0 || s.PendingCount() != 0 || s.ConnectionCount() != 0 {
			t.Error("resources remain after shutdown")
		}
	})
	return ln.Addr().String()
}

func TestConstructorValidatesSnapshot(t *testing.T) {
	cfg, fr := testServerConfig(t, "127.0.0.1:1")
	cfg.ListenAddr = ""
	s, err := NewWithDeps(cfg, access.NewPolicy(cfg, fr), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.forceCancel()
	if s.cfg.ListenAddr != "127.0.0.1:8080" || cfg.ListenAddr != "" {
		t.Fatal("default listener snapshot incorrect")
	}
	cfg.AllowedPorts = []int{}
	if _, err := NewWithDeps(cfg, nil, nil); err == nil {
		t.Fatal("empty allowed ports accepted")
	}
	cfg.AllowedPorts = nil
	cfg.Limits.MaxActive = int(^uint(0) >> 1)
	if _, err := NewWithDeps(cfg, nil, nil); err == nil {
		t.Fatal("constructor bypassed limits")
	}
}

func TestPendingAdmissionRecovery(t *testing.T) {
	cfg, fr := testServerConfig(t, "127.0.0.1:1")
	cfg.Limits.MaxPendingHandshakes = 2
	s, err := NewWithDeps(cfg, access.NewPolicy(cfg, fr), nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := startManagedGateway(t, s)
	held := make([]net.Conn, 0, 2)
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	waitFor(t, func() bool { return s.PendingCount() == 2 })
	for i := 0; i < 10; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		status, err := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if err != nil || !strings.Contains(status, "503") {
			t.Fatalf("overflow: %q %v", status, err)
		}
	}
	if s.ConnectionCount() != 2 {
		t.Fatalf("overflow sockets registered: %d", s.ConnectionCount())
	}
	for _, c := range held {
		c.Close()
	}
	waitFor(t, func() bool { return s.PendingCount() == 0 && s.ConnectionCount() == 0 })
	status, _ := connectThrough(t, addr, "example.com:443", basicAuth("pc-01", "wrong"), "")
	if !strings.Contains(status, "407") {
		t.Fatalf("recovery: %s", status)
	}
	waitFor(t, func() bool { return s.PendingCount() == 0 && s.ActiveCount() == 0 })
}

func TestDuplicateEmptyAuthorizationRejected(t *testing.T) {
	cfg, fr := testServerConfig(t, "127.0.0.1:1")
	s, err := NewWithDeps(cfg, access.NewPolicy(cfg, fr), nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := startManagedGateway(t, s)
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization:\r\nProxy-Authorization: "+basicAuth("pc-01", "secret-a")+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	status, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.Contains(status, "400") {
		t.Fatalf("duplicate auth: %q %v", status, err)
	}
}

func TestRelayOneWayTrafficExtendsIdle(t *testing.T) {
	client, a := net.Pipe()
	b, target := net.Pipe()
	defer client.Close()
	defer a.Close()
	defer b.Close()
	defer target.Close()
	done := make(chan struct{})
	go func() { relayTunnel(a, b, 300*time.Millisecond, 128); close(done) }()
	for i := 0; i < 8; i++ {
		write := make(chan error, 1)
		go func() {
			target.SetWriteDeadline(time.Now().Add(time.Second))
			_, err := target.Write([]byte("chunk"))
			write <- err
		}()
		client.SetReadDeadline(time.Now().Add(time.Second))
		data := make([]byte, 5)
		if _, err := io.ReadFull(client, data); err != nil {
			t.Fatal(err)
		}
		if err := <-write; err != nil {
			t.Fatal(err)
		}
		if string(data) != "chunk" {
			t.Fatal("corrupted stream")
		}
		time.Sleep(80 * time.Millisecond)
	}
	// Both directions now go idle; the relay must release both copies.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle relay leaked")
	}
}
