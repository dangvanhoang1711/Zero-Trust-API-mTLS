package main

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewReplayCache_DefaultTTL(t *testing.T) {
	cache := newReplayCache(0)
	if cache.ttl != 10*time.Minute {
		t.Errorf("expected default TTL 10m, got %v", cache.ttl)
	}
}

func TestNewReplayCache_CustomTTL(t *testing.T) {
	cache := newReplayCache(5 * time.Minute)
	if cache.ttl != 5*time.Minute {
		t.Errorf("expected TTL 5m, got %v", cache.ttl)
	}
}

func TestReplayCache_MarkIfNew_Success(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	err := cache.MarkIfNew("unique-jti-1")
	if err != nil {
		t.Errorf("expected no error for new jti, got %v", err)
	}
}

func TestReplayCache_MarkIfNew_Duplicate(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	jti := "duplicate-jti"

	// First use should succeed
	err := cache.MarkIfNew(jti)
	if err != nil {
		t.Errorf("expected no error for first use, got %v", err)
	}

	// Second use should fail
	err = cache.MarkIfNew(jti)
	if err == nil {
		t.Error("expected error for duplicate jti, got nil")
	}

	if err.Error() != "replay detected" {
		t.Errorf("expected 'replay detected' error, got %v", err)
	}
}

func TestReplayCache_MarkIfNew_EmptyJTI(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	err := cache.MarkIfNew("")
	if err == nil {
		t.Error("expected error for empty jti, got nil")
	}

	if err.Error() != "missing jti claim" {
		t.Errorf("expected 'missing jti claim' error, got %v", err)
	}
}

func TestReplayCache_MarkIfNew_WhitespaceJTI(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	err := cache.MarkIfNew("   ")
	if err == nil {
		t.Error("expected error for whitespace jti, got nil")
	}

	if err.Error() != "missing jti claim" {
		t.Errorf("expected 'missing jti claim' error, got %v", err)
	}
}

func TestReplayCache_MarkIfNew_MultipleUnique(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	jtis := []string{"jti-1", "jti-2", "jti-3", "jti-4", "jti-5"}

	for _, jti := range jtis {
		err := cache.MarkIfNew(jti)
		if err != nil {
			t.Errorf("expected no error for unique jti %s, got %v", jti, err)
		}
	}
}

func TestReplayCache_MarkIfNew_Concurrent(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)
	jti := "concurrent-jti"

	var wg sync.WaitGroup
	results := make(chan error, 10)

	// Launch 10 concurrent attempts to mark same jti
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cache.MarkIfNew(jti)
			results <- err
		}()
	}

	wg.Wait()
	close(results)

	// Exactly one should succeed
	successCount := 0
	failCount := 0
	for err := range results {
		if err == nil {
			successCount++
		} else {
			failCount++
		}
	}

	if successCount != 1 {
		t.Errorf("expected exactly 1 success, got %d", successCount)
	}

	if failCount != 9 {
		t.Errorf("expected exactly 9 failures, got %d", failCount)
	}
}

func TestReplayCache_MarkIfNew_ConcurrentUnique(t *testing.T) {
	cache := newReplayCache(10 * time.Minute)

	var wg sync.WaitGroup
	results := make(chan error, 100)

	// Launch 100 concurrent attempts with unique jtis
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			jti := fmt.Sprintf("concurrent-unique-jti-%d", id)
			err := cache.MarkIfNew(jti)
			results <- err
		}(i)
	}

	wg.Wait()
	close(results)

	// All should succeed
	for err := range results {
		if err != nil {
			t.Errorf("expected no error for unique concurrent jti, got %v", err)
		}
	}
}

func TestReplayCache_Eviction(t *testing.T) {
	// Use very short TTL for testing
	cache := newReplayCache(100 * time.Millisecond)

	// Mark first jti
	err := cache.MarkIfNew("jti-1")
	if err != nil {
		t.Errorf("expected no error for jti-1, got %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Mark second jti to trigger eviction
	err = cache.MarkIfNew("jti-2")
	if err != nil {
		t.Errorf("expected no error for jti-2, got %v", err)
	}

	// First jti should now be evicted and can be reused
	err = cache.MarkIfNew("jti-1")
	if err != nil {
		t.Errorf("expected no error for jti-1 after eviction, got %v", err)
	}
}

func BenchmarkReplayCache_MarkIfNew(b *testing.B) {
	cache := newReplayCache(10 * time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jti := fmt.Sprintf("benchmark-jti-%d", i)
		_ = cache.MarkIfNew(jti)
	}
}

func BenchmarkReplayCache_MarkIfNew_Parallel(b *testing.B) {
	cache := newReplayCache(10 * time.Minute)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			jti := fmt.Sprintf("parallel-jti-%d", i)
			_ = cache.MarkIfNew(jti)
			i++
		}
	})
}

func BenchmarkReplayCache_MarkIfNew_Duplicate(b *testing.B) {
	cache := newReplayCache(10 * time.Minute)
	jti := "duplicate-benchmark-jti"

	// Pre-populate
	_ = cache.MarkIfNew(jti)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.MarkIfNew(jti)
	}
}
