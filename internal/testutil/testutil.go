package testutil

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gekok/vps-egress-gateway/internal/access"
)

type FakeResolver struct {
	mu    sync.Mutex
	IPs   map[string][]net.IP
	Err   error
	Calls int
}

func (f *FakeResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	f.mu.Lock()
	f.Calls++
	f.mu.Unlock()
	if f.Err != nil {
		return nil, f.Err
	}
	return f.IPs[host], nil
}

func (f *FakeResolver) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Calls
}

type SpyDialer struct {
	mu       sync.Mutex
	Addrs    []string
	DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (s *SpyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	s.mu.Lock()
	s.Addrs = append(s.Addrs, addr)
	fn := s.DialFunc
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx, network, addr)
	}
	d := &net.Dialer{}
	return d.DialContext(ctx, network, addr)
}

func (s *SpyDialer) Addresses() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Addrs...)
}

type FakeUpstream struct {
	Listener   net.Listener
	Addr       string
	Mode       string
	TargetAddr string
	Username   string
	Password   string
	GotAuth    []string
	GotDest    []string
	mu         sync.Mutex
	wg         sync.WaitGroup
	closed     chan struct{}
}

func StartFakeHTTPUpstream(t *testing.T, mode, targetAddr, username, password string) *FakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake upstream: %v", err)
	}
	f := &FakeUpstream{Listener: ln, Addr: ln.Addr().String(), Mode: mode, TargetAddr: targetAddr, Username: username, Password: password, closed: make(chan struct{})}
	f.wg.Add(1)
	go f.serve()
	t.Cleanup(func() { f.Close() })
	return f
}

func (f *FakeUpstream) Close() {
	select {
	case <-f.closed:
	default:
		close(f.closed)
		f.Listener.Close()
		f.wg.Wait()
	}
}

func (f *FakeUpstream) serve() {
	defer f.wg.Done()
	for {
		c, err := f.Listener.Accept()
		if err != nil {
			return
		}
		f.wg.Add(1)
		go func(conn net.Conn) {
			defer f.wg.Done()
			defer conn.Close()
			f.handle(conn)
		}(c)
	}
}

func (f *FakeUpstream) handle(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(conn, 8192)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimSpace(reqLine), " ", 3)
	if len(parts) != 3 || parts[0] != "CONNECT" {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	dest := parts[1]
	var auth string
	total := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		total += len(line)
		if total > 32768 {
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			if strings.EqualFold(strings.TrimSpace(line[:idx]), "Proxy-Authorization") {
				auth = strings.TrimSpace(line[idx+1:])
			}
		}
	}
	f.mu.Lock()
	f.GotAuth = append(f.GotAuth, auth)
	f.GotDest = append(f.GotDest, dest)
	f.mu.Unlock()
	if f.Username != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(f.Username+":"+f.Password))
		if auth != want {
			io.WriteString(conn, "HTTP/1.1 407 Proxy Auth Required\r\n\r\n")
			return
		}
	}
	switch f.Mode {
	case "ok":
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		if f.TargetAddr != "" {
			up, err := net.DialTimeout("tcp", f.TargetAddr, 5*time.Second)
			if err != nil {
				return
			}
			defer up.Close()
			conn.SetDeadline(time.Time{})
			relay(conn, up)
			return
		}
		conn.SetDeadline(time.Time{})
		echoConn(conn, br)
	case "ok-buffered":
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\nHELLO-BUFFERED:")
		conn.SetDeadline(time.Time{})
		echoConn(conn, br)
	case "reject503":
		io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\n\r\n")
	case "stall":
		time.Sleep(2 * time.Second)
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		conn.SetDeadline(time.Time{})
		echoConn(conn, br)
	case "malformed":
		io.WriteString(conn, "NOT-HTTP garbage\r\n\r\n")
	case "oversized":
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n")
		for i := 0; i < 2000; i++ {
			fmt.Fprintf(conn, "X-Pad-%04d: %s\r\n", i, strings.Repeat("A", 64))
		}
		io.WriteString(conn, "\r\n")
	default:
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		conn.SetDeadline(time.Time{})
		echoConn(conn, br)
	}
}

func echoConn(conn net.Conn, br *bufio.Reader) {
	if br.Buffered() > 0 {
		n := br.Buffered()
		peeked, _ := br.Peek(n)
		conn.Write(peeked)
		br.Discard(n)
	}
	buf := make([]byte, 32768)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(b, a); tryClose(a); tryClose(b) }()
	go func() { defer wg.Done(); io.Copy(a, b); tryClose(a); tryClose(b) }()
	wg.Wait()
}

func tryClose(c net.Conn) {
	if c == nil {
		return
	}
	_ = c.SetDeadline(time.Now())
	_ = c.Close()
}

func StartEchoServer(t *testing.T, marker string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.WriteString(conn, marker+"\n")
				io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func GenerateCA(t *testing.T) (certPEM, keyPEM []byte, cert *x509.Certificate, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, cert, key
}

func StartTLSEchoServer(t *testing.T, marker string) (string, []byte) {
	t.Helper()
	caPEM, _, caCert, caKey := GenerateCA(t)
	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.WriteString(conn, marker+"\n")
				io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln.Addr().String(), caPEM
}

// Destinations returns the CONNECT targets this fake upstream was asked for.
func (f *FakeUpstream) Destinations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.GotDest...)
}

// StartSilentTCP accepts connections and then never writes a byte, modelling an
// upstream that completes the TCP handshake and then goes dark.
func StartSilentTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen silent: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var held []net.Conn
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	return ln.Addr().String()
}

// StartUnterminatedHeader answers a CONNECT with bytes that never contain a
// newline, modelling an upstream that can exhaust a naive line reader.
func StartUnterminatedHeader(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen unterminated: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				junk := []byte(strings.Repeat("A", 4096))
				for {
					conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
					if _, err := conn.Write(junk); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

var _ = access.SystemResolver
