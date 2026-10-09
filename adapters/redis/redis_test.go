package redis_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/redis"
	"github.com/BladiCreator/go-modular-auth/cache"
)

type mockRedisClient struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMockClient() *mockRedisClient {
	return &mockRedisClient{data: map[string][]byte{}}
}

func (m *mockRedisClient) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.data[key]
	if !ok {
		return nil, cache.ErrMiss
	}
	return b, nil
}

func (m *mockRedisClient) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *mockRedisClient) Del(ctx context.Context, keys ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		delete(m.data, k)
	}
	return nil
}

func (m *mockRedisClient) IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return delta, nil
}

func TestRedisCache_RoundTrip(t *testing.T) {
	client := newMockClient()
	c := redis.New(client)
	ctx := context.Background()

	type Item struct {
		Name string `json:"name"`
	}

	// 1. Get miss
	var dest Item
	err := c.Get(ctx, "nonexistent", &dest)
	if !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("expected ErrMiss, got %v", err)
	}

	// 2. Set and Get
	err = c.Set(ctx, "user:1", Item{Name: "Alice"}, time.Minute)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	err = c.Get(ctx, "user:1", &dest)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if dest.Name != "Alice" {
		t.Errorf("expected Alice, got %s", dest.Name)
	}

	// 3. Counter increment
	val, err := c.Increment(ctx, "rate:ip", 5, time.Minute)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}
	if val != 5 {
		t.Errorf("expected 5, got %d", val)
	}

	// 4. Delete
	err = c.Delete(ctx, "user:1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	err = c.Get(ctx, "user:1", &dest)
	if !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("expected ErrMiss after delete, got %v", err)
	}
}
