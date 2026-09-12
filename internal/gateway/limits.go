package gateway

import (
	"fmt"
	"sync"
	"time"
)

type limiter struct {
	mu           sync.Mutex
	maxActive    int
	active       int
	perClient    map[string]int
	maxPerClient int
	maxNewPerSec int
	tokens       float64
	last         time.Time
}

func newLimiter(maxActive, maxPerClient, maxNewPerSec int) *limiter {
	return &limiter{maxActive: maxActive, perClient: map[string]int{}, maxPerClient: maxPerClient, maxNewPerSec: maxNewPerSec, tokens: float64(maxNewPerSec), last: time.Now()}
}

func (l *limiter) acquire(client string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(l.last).Seconds()
	l.last = now
	l.tokens += elapsed * float64(l.maxNewPerSec)
	if l.tokens > float64(l.maxNewPerSec) {
		l.tokens = float64(l.maxNewPerSec)
	}
	if l.tokens < 1 {
		return fmt.Errorf("rate limited")
	}
	if l.active >= l.maxActive {
		return fmt.Errorf("too many tunnels")
	}
	if l.perClient[client] >= l.maxPerClient {
		return fmt.Errorf("too many tunnels for client")
	}
	l.tokens -= 1
	l.active++
	l.perClient[client]++
	return nil
}

func (l *limiter) release(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active > 0 {
		l.active--
	}
	if l.perClient[client] > 0 {
		l.perClient[client]--
		if l.perClient[client] == 0 {
			delete(l.perClient, client)
		}
	}
}

func (l *limiter) counts() (int, map[string]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := make(map[string]int, len(l.perClient))
	for k, v := range l.perClient {
		cp[k] = v
	}
	return l.active, cp
}
