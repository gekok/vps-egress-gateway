package upstream

import (
	"context"
	"fmt"
	"net"
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
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	var auth *proxy.Auth
	if d.username != "" {
		auth = &proxy.Auth{User: d.username, Password: d.password}
	}
	base := &net.Dialer{}
	fwd := &socksFwdDialer{ctx: ctx, base: base, upstream: d.upstreamAddr}
	dialer, err := proxy.SOCKS5("tcp", d.upstreamAddr, auth, fwd)
	if err != nil {
		return nil, nil, fmt.Errorf("socks5 setup: %w", err)
	}
	dest := fmt.Sprintf("%s:%d", target.PinnedIP.String(), target.Port)
	conn, err := dialer.Dial("tcp", dest)
	if err != nil {
		return nil, nil, fmt.Errorf("socks5 connect: %w", err)
	}
	_ = time.Now()
	return conn, nil, nil
}

type socksFwdDialer struct {
	ctx      context.Context
	base     *net.Dialer
	upstream string
}

func (f *socksFwdDialer) Dial(network, addr string) (net.Conn, error) {
	return f.base.DialContext(f.ctx, network, f.upstream)
}
