package upstream

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
	"github.com/gekok/vps-egress-gateway/internal/config"
)

type Dialer interface {
	Dial(ctx context.Context, target access.Target) (net.Conn, []byte, error)
}

type Factory struct {
	Cfg         *config.Config
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	Timeout     time.Duration
}

func NewDialer(cfg *config.Config) (Dialer, error) {
	return NewDialerWithNet(cfg, nil)
}

func NewDialerWithNet(cfg *config.Config, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (Dialer, error) {
	hs := time.Duration(cfg.Timeouts.HandshakeMs) * time.Millisecond
	if hs <= 0 {
		hs = 8 * time.Second
	}
	dm := time.Duration(cfg.Timeouts.DialMs) * time.Millisecond
	if dm <= 0 {
		dm = 8 * time.Second
	}
	base := dial
	if base == nil {
		d := &net.Dialer{Timeout: dm}
		base = d.DialContext
	}
	user, pass := cfg.UpstreamCredentials()
	addr := fmt.Sprintf("%s:%d", cfg.Upstream.Host, cfg.Upstream.Port)
	switch cfg.Upstream.Protocol {
	case config.ProtocolHTTP:
		return &httpDialer{upstreamAddr: addr, username: user, password: pass, dial: base, timeout: hs}, nil
	case config.ProtocolHTTPS:
		caFile := cfg.Upstream.CAFile
		serverName := cfg.Upstream.ServerName
		if serverName == "" {
			serverName = cfg.Upstream.Host
		}
		return &httpsDialer{upstreamAddr: addr, serverName: serverName, caFile: caFile, username: user, password: pass, dial: base, timeout: hs}, nil
	case config.ProtocolSOCKS5:
		return &socks5Dialer{upstreamAddr: addr, username: user, password: pass, dial: base, timeout: hs}, nil
	default:
		return nil, fmt.Errorf("unsupported upstream protocol")
	}
}
