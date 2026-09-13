package testutil

import (
	"net"
	"sync"
	"testing"
	"time"
)

// Serve owns the listener, every accepted socket, and all handler goroutines.
// Cleanup works even when a test fails during a handshake or a peer stays idle.
func Serve(t testing.TB, ln net.Listener, handle func(net.Conn)) func() {
	t.Helper()
	var mu sync.Mutex
	conns := make(map[net.Conn]struct{})
	closing := false
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closing {
				mu.Unlock()
				conn.Close()
				return
			}
			conns[conn] = struct{}{}
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer func() { conn.Close(); mu.Lock(); delete(conns, conn); mu.Unlock() }()
				handle(conn)
			}()
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			ln.Close()
			mu.Lock()
			closing = true
			for c := range conns {
				c.SetDeadline(time.Now())
				c.Close()
			}
			mu.Unlock()
			wg.Wait()
		})
	}
	t.Cleanup(stop)
	return stop
}
