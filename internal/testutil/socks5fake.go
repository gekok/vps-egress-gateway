package testutil

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type FakeSOCKS5 struct {
	Listener   net.Listener
	Addr       string
	Username   string
	Password   string
	TargetAddr string
	DialTarget func(host string, port int) (net.Conn, error)
}

func StartFakeSOCKS5(t *testing.T, username, password, targetAddr string) *FakeSOCKS5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}
	f := &FakeSOCKS5{Listener: ln, Addr: ln.Addr().String(), Username: username, Password: password, TargetAddr: targetAddr}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	return f
}

func (f *FakeSOCKS5) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	needAuth := f.Username != ""
	hasNoAuth := false
	hasUser := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
		}
		if m == 0x02 {
			hasUser = true
		}
	}
	if needAuth {
		if !hasUser {
			conn.Write([]byte{0x05, 0xFF})
			return
		}
		conn.Write([]byte{0x05, 0x02})
		ahdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, ahdr); err != nil {
			return
		}
		ulen := int(ahdr[1])
		ubuf := make([]byte, ulen)
		if _, err := io.ReadFull(conn, ubuf); err != nil {
			return
		}
		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, plenBuf); err != nil {
			return
		}
		pbuf := make([]byte, int(plenBuf[0]))
		if _, err := io.ReadFull(conn, pbuf); err != nil {
			return
		}
		if string(ubuf) != f.Username || string(pbuf) != f.Password {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		conn.Write([]byte{0x01, 0x00})
	} else {
		if !hasNoAuth {
			conn.Write([]byte{0x05, 0xFF})
			return
		}
		conn.Write([]byte{0x05, 0x00})
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	case 0x03:
		lb := make([]byte, 1)
		io.ReadFull(conn, lb)
		b := make([]byte, int(lb[0]))
		io.ReadFull(conn, b)
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	io.ReadFull(conn, pb)
	port := int(binary.BigEndian.Uint16(pb))
	_ = host
	_ = port
	var target net.Conn
	var err error
	if f.DialTarget != nil {
		target, err = f.DialTarget(host, port)
	} else if f.TargetAddr != "" {
		target, err = net.DialTimeout("tcp", f.TargetAddr, 5*time.Second)
	} else {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
	conn.SetDeadline(time.Time{})
	relay(conn, target)
}

var _ = fmt.Sprint
