package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
)

type httpDialer struct {
	upstreamAddr string
	username     string
	password     string
	dial         func(ctx context.Context, network, addr string) (net.Conn, error)
	timeout      time.Duration
}

func (d *httpDialer) Dial(ctx context.Context, target access.Target) (net.Conn, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	conn, err := d.dial(ctx, "tcp", d.upstreamAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial upstream")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	targetAddr := target.PinnedIP.String() + ":" + fmt.Sprint(target.Port)
	var sb strings.Builder
	sb.WriteString("CONNECT " + targetAddr + " HTTP/1.1\r\n")
	sb.WriteString("Host: " + target.Hostname + ":" + fmt.Sprint(target.Port) + "\r\n")
	if d.username != "" {
		cred := d.username + ":" + d.password
		sb.WriteString("Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(cred)) + "\r\n")
	}
	sb.WriteString("Proxy-Connection: Keep-Alive\r\n\r\n")
	if _, err := io.WriteString(conn, sb.String()); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write connect")
	}
	br := bufio.NewReaderSize(conn, 8192)
	code, err := readConnectStatus(br, 32768)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if code != 200 {
		conn.Close()
		return nil, nil, fmt.Errorf("upstream rejected")
	}
	n := br.Buffered()
	var prefix []byte
	if n > 0 {
		peeked, _ := br.Peek(n)
		prefix = append([]byte(nil), peeked...)
	}
	return &bufferedConn{Conn: conn, reader: br, prefix: prefix}, prefix, nil
}

func readConnectStatus(br *bufio.Reader, maxHeader int) (int, error) {
	total := 0
	var statusLine string
	first := true
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, fmt.Errorf("read upstream response")
		}
		total += len(line)
		if total > maxHeader {
			return 0, fmt.Errorf("upstream response header too large")
		}
		if first {
			statusLine = line
			first = false
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	s := strings.TrimSpace(statusLine)
	parts := strings.SplitN(s, " ", 3)
	if len(parts) < 2 || len(parts[0]) < 5 || parts[0][:5] != "HTTP/" {
		return 0, fmt.Errorf("malformed upstream response")
	}
	var code int
	fmt.Sscanf(parts[1], "%d", &code)
	if code == 0 {
		return 0, fmt.Errorf("malformed upstream status")
	}
	return code, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
	prefix []byte
	offset int
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	if c.offset < len(c.prefix) {
		n := copy(b, c.prefix[c.offset:])
		c.offset += n
		if c.offset >= len(c.prefix) {
			c.prefix = nil
		}
		return n, nil
	}
	return c.reader.Read(b)
}
