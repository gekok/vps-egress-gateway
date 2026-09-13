package gateway

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Idle means no traffic in either direction, not silence in one direction.
// This matters for a client awaiting a long, continuously streamed response.
func relayTunnel(a, b net.Conn, idle time.Duration, bufSize int) (int64, int64) {
	var mu sync.Mutex
	lastActivity := time.Now()
	touch := func() {
		mu.Lock()
		defer mu.Unlock()
		lastActivity = time.Now()
		if idle > 0 {
			deadline := lastActivity.Add(idle)
			a.SetReadDeadline(deadline)
			b.SetReadDeadline(deadline)
		}
	}
	touch()
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			a.SetDeadline(time.Now())
			b.SetDeadline(time.Now())
			a.Close()
			b.Close()
		})
	}
	copyDirection := func(dst, src net.Conn) int64 {
		buf := make([]byte, bufSize)
		var total int64
		for {
			n, readErr := src.Read(buf)
			if n > 0 {
				touch()
				dst.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
				written, writeErr := dst.Write(buf[:n])
				total += int64(written)
				if writeErr != nil || written != n {
					closeBoth()
					return total
				}
				touch()
			}
			if readErr == nil {
				continue
			}
			if errors.Is(readErr, io.EOF) {
				// EOF closes only this direction. The server may send its response
				// after observing the client's FIN; retain that response channel.
				if half, ok := dst.(interface{ CloseWrite() error }); ok {
					dst.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
					if half.CloseWrite() == nil {
						return total
					}
				}
			} else if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
				mu.Lock()
				active := idle > 0 && time.Since(lastActivity) < idle
				mu.Unlock()
				if active {
					continue
				}
			}
			closeBoth()
			return total
		}
	}
	var c1, c2 int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c1 = copyDirection(b, a) }()
	go func() { defer wg.Done(); c2 = copyDirection(a, b) }()
	wg.Wait()
	return c1, c2
}
