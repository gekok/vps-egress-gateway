package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
)

type httpsDialer struct {
	upstreamAddr string
	serverName   string
	caFile       string
	username     string
	password     string
	dial         func(ctx context.Context, network, addr string) (net.Conn, error)
	timeout      time.Duration
}

func (d *httpsDialer) Dial(ctx context.Context, target access.Target) (net.Conn, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	raw, err := d.dial(ctx, "tcp", d.upstreamAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial upstream: %w", err)
	}
	tlsCfg := &tls.Config{ServerName: d.serverName, MinVersion: tls.VersionTLS12}
	if d.caFile != "" {
		pemData, err := os.ReadFile(d.caFile)
		if err != nil {
			raw.Close()
			return nil, nil, fmt.Errorf("read ca bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			raw.Close()
			return nil, nil, fmt.Errorf("invalid ca bundle")
		}
		tlsCfg.RootCAs = pool
	}
	tlsConn := tls.Client(raw, tlsCfg)
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("tls handshake to upstream: %w", err)
	}
	if err := tlsConn.VerifyHostname(d.serverName); err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("upstream certificate verify: %w", err)
	}
	inner := &httpDialer{upstreamAddr: d.upstreamAddr, username: d.username, password: d.password, dial: func(c context.Context, n, a string) (net.Conn, error) { return tlsConn, nil }, timeout: d.timeout}
	conn, buffered, err := inner.Dial(ctx, target)
	if err != nil {
		tlsConn.Close()
		return nil, nil, err
	}
	return conn, buffered, nil
}
