package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/cache"
	"github.com/BladiCreator/go-modular-auth/cache/memory"
)

func TestTTLAndMiss(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(0, 0)
	c := memory.New(memory.WithClock(func() time.Time { return now }))

	if err := c.Set(ctx, cache.Key("x"), "v", 0); !errors.Is(err, memory.ErrInvalidTTL) {
		t.Fatalf("entries without ttl must be rejected: %v", err)
	}
	_ = c.Set(ctx, cache.Key("x"), map[string]int{"a": 1}, time.Second)
	var got map[string]int
	if err := c.Get(ctx, cache.Key("x"), &got); err != nil || got["a"] != 1 {
		t.Fatalf("Get: %v %v", got, err)
	}
	now = now.Add(time.Second)
	if err := c.Get(ctx, cache.Key("x"), &got); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("want miss after ttl, got %v", err)
	}
}

func TestCounterFixedWindow(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(0, 0)
	c := memory.New(memory.WithClock(func() time.Time { return now }))
	k := cache.Key("ratelimit", "signin", "ip")
	for i := 1; i <= 3; i++ {
		n, err := c.Increment(ctx, k, 1, time.Minute)
		if err != nil || n != int64(i) {
			t.Fatalf("Increment = %d, %v", n, err)
		}
	}
	now = now.Add(time.Minute)
	if n, _ := c.Increment(ctx, k, 1, time.Minute); n != 1 {
		t.Fatalf("window must reset, got %d", n)
	}
}

func TestKeyNamespace(t *testing.T) {
	if got := cache.Key("session", "abc"); got != "gomodularauth:session:abc" {
		t.Fatalf("got %q", got)
	}
}
