package cache

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type bucket struct {
	startAt time.Time
	count   int
}

type RateLimiter struct {
	mu    sync.Mutex
	state map[string]*bucket
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		state: make(map[string]*bucket),
	}
}

func (r *RateLimiter) Allow(identity string, maxRequests int, window time.Duration) bool {
	if maxRequests <= 0 {
		return true
	}
	if strings.TrimSpace(identity) == "" {
		return false
	}
	if window <= 0 {
		return true
	}

	now := time.Now().UTC()
	key := fmt.Sprintf("%d|%s|%d", maxRequests, strings.TrimSpace(identity), window.Milliseconds())

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.state[key]
	if !ok {
		r.state[key] = &bucket{
			startAt: now,
			count:   1,
		}
		return true
	}

	if now.Sub(entry.startAt) >= window {
		entry.startAt = now
		entry.count = 1
		return true
	}

	if entry.count >= maxRequests {
		return false
	}

	entry.count++
	return true
}
