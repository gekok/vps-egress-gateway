package upstream

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
	"golang.org/x/net/proxy"
)

type socks5Dialer struct {
	upstreamAddr string
	username     string
	password     string
	dial         func(ctx context.Context, network, addr string) (net.Conn, error)
	timeout      time.Duration
}

func (d *socks5Dialer) Dial(ctx context.Context, target access.Target) (net.Conn, []byte, error) {
	raw, err := d.dial(ctx, "tcp", d.upstreamAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial socks5 upstream: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	finish := guardHandshake(ctx, raw)
	defer finish()
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	var auth *proxy.Auth
	if d.username != "" {
		auth = &proxy.Auth{User: d.username, Password: d.password}
	}
	dialer, err := proxy.SOCKS5("tcp", d.upstreamAddr, auth, &socksFwdDialer{dial: func(context.Context, string, string) (net.Conn, error) { return raw, nil }, upstream: d.upstreamAddr})
	if err != nil {
		return nil, nil, fmt.Errorf("socks5 setup: %w", err)
	}
	// proxy.Dialer.Dial runs the SOCKS5 greeting/auth/connect exchange under
	// context.Background(), so an upstream that accepts TCP and then goes
	// silent would hang the tunnel forever. DialContext applies our deadline to
	// the handshake itself.
	cd, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, nil, fmt.Errorf("socks5 dialer does not support context")
	}
	dest := net.JoinHostPort(target.PinnedIP.String(), strconv.Itoa(target.Port))
	_, err = cd.DialContext(ctx, "tcp", dest)
	if err != nil {
		return nil, nil, fmt.Errorf("socks5 connect: %w", err)
	}
	if err := finish(); err != nil {
		return nil, nil, fmt.Errorf("finish socks5 handshake: %w", err)
	}
	success = true
	// x/net's socks.Conn hides CloseWrite. Its handshake uses exact-length
	// reads, so returning raw preserves half-close without discarding data.
	return raw, nil, nil
}

// socksFwdDialer forces every SOCKS5 transport dial through the injected dialer
// and pins the destination to the configured upstream, so no code path can open
// a socket to the tunnel's destination even if the SOCKS library changes.
type socksFwdDialer struct {
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	upstream string
}

func (f *socksFwdDialer) Dial(network, addr string) (net.Conn, error) {
	return f.DialContext(context.Background(), network, addr)
}

func (f *socksFwdDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return f.dial(ctx, network, f.upstream)
}
