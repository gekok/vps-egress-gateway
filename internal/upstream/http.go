package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
)

// maxUpstreamHeaderBytes caps the CONNECT response head we are willing to read
// from the upstream proxy, including a head that never terminates.
const maxUpstreamHeaderBytes = 32768

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
		return nil, nil, fmt.Errorf("dial upstream %s: %w", d.upstreamAddr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	port := strconv.Itoa(target.Port)
	targetAddr := net.JoinHostPort(target.PinnedIP.String(), port)
	var sb strings.Builder
	sb.WriteString("CONNECT " + targetAddr + " HTTP/1.1\r\n")
	sb.WriteString("Host: " + net.JoinHostPort(target.Hostname, port) + "\r\n")
	if d.username != "" {
		cred := d.username + ":" + d.password
		sb.WriteString("Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(cred)) + "\r\n")
	}
	sb.WriteString("Proxy-Connection: Keep-Alive\r\n\r\n")
	if _, err := io.WriteString(conn, sb.String()); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write connect to upstream: %w", err)
	}
	br := bufio.NewReaderSize(conn, 8192)
	code, err := readConnectStatus(br, maxUpstreamHeaderBytes)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if code != 200 {
		conn.Close()
		return nil, nil, fmt.Errorf("upstream rejected CONNECT with status %d", code)
	}
	// Bytes the upstream packed into the same read as the CONNECT response are
	// early tunnel data. Hand them back exactly once and drain them from the
	// reader, otherwise the relay would deliver the same bytes again and
	// corrupt the client's TLS handshake.
	var early []byte
	if n := br.Buffered(); n > 0 {
		peeked, _ := br.Peek(n)
		early = append([]byte(nil), peeked...)
		_, _ = br.Discard(n)
	}
	return &bufferedConn{Conn: conn, reader: br}, early, nil
}

var errLineTooLong = errors.New("line too long")

// readLineLimited reads one '\n'-terminated line while capping how many bytes a
// peer that never sends a newline can make us buffer.
func readLineLimited(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		chunk, err := br.ReadSlice('\n')
		if sb.Len()+len(chunk) > max {
			return "", errLineTooLong
		}
		sb.Write(chunk)
		if err == nil {
			return sb.String(), nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return "", err
	}
}

func readConnectStatus(br *bufio.Reader, maxHeader int) (int, error) {
	total := 0
	var statusLine string
	first := true
	for {
		line, err := readLineLimited(br, maxHeader)
		if err != nil {
			return 0, fmt.Errorf("read upstream CONNECT response: %w", err)
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
	code, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || code <= 0 {
		return 0, fmt.Errorf("malformed upstream status")
	}
	return code, nil
}

// bufferedConn keeps reads flowing through the bufio.Reader used for the
// CONNECT handshake, so bytes it already buffered are not lost.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}
