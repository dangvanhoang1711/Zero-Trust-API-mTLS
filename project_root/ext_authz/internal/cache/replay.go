package cache

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"ext-authz/internal/auth"
)

type replayCacheBackend interface {
	markIfNew(ctx context.Context, jti string, ttl time.Duration, maxEntries int) (bool, error)
}

// ReplayCache prevents replay attacks by tracking JWT ID (jti) claim values
// observed for the configured TTL window.
//
// Notes:
// - This implementation uses in-memory storage, suitable for single-instance
//   deployments and CI-style validation.
// - For production scale-out, Redis-backed storage is enabled when configured.
type ReplayCache struct {
	ttl   time.Duration
	max   int
	mu    sync.Mutex
	items map[string]time.Time
	last  time.Time

	backend    replayCacheBackend
	fallback   *ReplayCache
	backendCfg string
}

const (
	defaultReplayTTL         = 10 * time.Minute
	defaultReplayMaxEntries  = 10000
	defaultRedisKeyPrefix    = "zero-trust:replay"
	inMemoryBackend          = "memory"
	redisBackend             = "redis"
)

func sanitizeReplayBackend(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return inMemoryBackend
	case inMemoryBackend:
		return inMemoryBackend
	case redisBackend:
		return redisBackend
	default:
		return inMemoryBackend
	}
}

// NewReplayCache creates a replay cache with in-memory backend by default.
func NewReplayCache(ttl time.Duration, maxEntries ...int) *ReplayCache {
	maxCacheEntries := resolveReplayMaxEntries(maxEntries...)
	return NewReplayCacheWithConfig(ttl, maxCacheEntries, inMemoryBackend, "", defaultRedisKeyPrefix)
}

// NewReplayCacheWithConfig creates a replay cache with an optional backend.
// Supported backends: in-memory (default) and Redis-backed with `redis`.
func NewReplayCacheWithConfig(
	ttl time.Duration,
	maxEntries int,
	backend string,
	redisURL string,
	redisKeyPrefix string,
) *ReplayCache {
	maxCacheEntries := resolveReplayMaxEntries(maxEntries)
	backend = sanitizeReplayBackend(backend)

	base := newInMemoryReplayCache(ttl, maxCacheEntries)
	base.backendCfg = backend

	if backend != redisBackend {
		return base
	}

	redisBackendImpl, err := newRedisReplayBackend(redisURL, redisKeyPrefix)
	if err != nil {
		return base
	}

	base.backend = redisBackendImpl
	base.fallback = newInMemoryReplayCache(ttl, maxCacheEntries)
	base.backendCfg = redisBackend
	return base
}

func newInMemoryReplayCache(ttl time.Duration, maxEntries int) *ReplayCache {
	if ttl <= 0 {
		ttl = defaultReplayTTL
	}
	if maxEntries <= 0 {
		maxEntries = defaultReplayMaxEntries
	}
	return &ReplayCache{
		ttl:   ttl,
		max:   maxEntries,
		items: make(map[string]time.Time, 256),
		last:  time.Now(),
	}
}

func resolveReplayMaxEntries(values ...int) int {
	if len(values) == 0 || values[0] <= 0 {
		return defaultReplayMaxEntries
	}
	return values[0]
}

// MarkIfNew records a JTI if it has not been seen within ttl.
// Returns AuthError when the claim is missing or replayed.
func (c *ReplayCache) MarkIfNew(jti string) error {
	if strings.TrimSpace(jti) == "" {
		return &auth.AuthError{HTTPStatus: http.StatusUnauthorized, Message: "missing jti claim"}
	}

	now := time.Now()
	normalizedJTI := strings.TrimSpace(jti)

	if c == nil {
		return &auth.AuthError{HTTPStatus: http.StatusInternalServerError, Message: "replay cache unavailable"}
	}

	if c.backend != nil {
		ok, err := c.backend.markIfNew(context.Background(), normalizedJTI, c.ttl, c.max)
		if err != nil {
			// Redis backend is optional for HA. If it fails, we prefer availability with local cache.
			if c.fallback != nil {
				log.Printf("WARN: redis replay backend unavailable, falling back to in-memory cache: %v", err)
				return c.fallback.MarkIfNew(normalizedJTI)
			}
			return &auth.AuthError{HTTPStatus: http.StatusInternalServerError, Message: "replay cache backend unavailable"}
		}
		if !ok {
			return &auth.AuthError{HTTPStatus: http.StatusForbidden, Message: "replay detected"}
		}
		return nil
	}

	return c.markIfNewInMemory(normalizedJTI, now)
}

func (c *ReplayCache) markIfNewInMemory(jti string, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.purgeExpired(now)

	if _, exists := c.items[jti]; exists {
		return &auth.AuthError{HTTPStatus: http.StatusForbidden, Message: "replay detected"}
	}

	if len(c.items) >= c.max {
		c.evictOldest()
	}
	c.items[jti] = now
	return nil
}

func (c *ReplayCache) purgeExpired(now time.Time) {
	if now.Sub(c.last) < c.ttl {
		return
	}

	cutoff := now.Add(-c.ttl)
	for key, seenAt := range c.items {
		if seenAt.Before(cutoff) {
			delete(c.items, key)
		}
	}
	c.last = now
}

func (c *ReplayCache) evictOldest() {
	var oldestJTI string
	var oldestSeen time.Time

	for key, seenAt := range c.items {
		if oldestJTI == "" || seenAt.Before(oldestSeen) {
			oldestJTI = key
			oldestSeen = seenAt
		}
	}

	if oldestJTI != "" {
		delete(c.items, oldestJTI)
	}
}
