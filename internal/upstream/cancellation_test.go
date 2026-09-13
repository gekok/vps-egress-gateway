package upstream

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/testutil"
)

func TestHTTPHandshakeCancellationClosesSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	closed := make(chan struct{})
	testutil.Serve(t, ln, func(c net.Conn) {
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		close(started)
		io.Copy(io.Discard, br)
		close(closed)
	})
	cfg := cfgHTTP(ln.Addr().String())
	cfg.Timeouts.HandshakeMs = 60000
	d, err := NewDialer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, _, err := d.Dial(ctx, publicTarget())
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("handshake did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for handshake timeout")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("upstream socket leaked")
	}
}
