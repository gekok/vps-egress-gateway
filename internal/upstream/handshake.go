package upstream

import (
	"context"
	"net"
	"sync"
	"time"
)

// A deadline alone does not wake I/O when a context is cancelled early. Join
// the cancellation callback before handing the socket to its relay owner.
func guardHandshake(ctx context.Context, conn net.Conn) func() error {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
		close(done)
	})
	var once sync.Once
	var err error
	return func() error {
		once.Do(func() {
			if !stop() {
				<-done
			}
			err = ctx.Err()
			if err == nil {
				err = conn.SetDeadline(time.Time{})
			}
		})
		return err
	}
}
