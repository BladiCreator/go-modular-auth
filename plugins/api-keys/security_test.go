package apikeys_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	apikeys "github.com/BladiCreator/go-modular-auth/plugins/api-keys"
	"github.com/BladiCreator/go-modular-auth/plugins/api-keys/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func TestSecurity_BruteForceProtection(t *testing.T) {
	ctx := context.Background()
	ad := adaptermem.New()
	memCache := corecache.New()

	engine, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   memCache,
		Plugins: []auth.PluginModule{
			apikeys.New(
				apikeys.WithBruteForceProtection(3, 1*time.Minute),
			),
		},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	apiKeys, err := auth.Get[plugins.APIKeys](engine)
	if err != nil {
		t.Fatalf("auth.Get failed: %v", err)
	}

	ipAttacker := "203.0.113.195"

	// 3 consecutive failed attempts
	for i := 1; i <= 3; i++ {
		_, err := apiKeys.Authenticate(ctx, "gma_bad_key_attempt", apikeys.WithIPAddress(ipAttacker))
		if !errors.Is(err, apikeys.ErrInvalidKey) {
			t.Fatalf("attempt %d: expected ErrInvalidKey, got %v", i, err)
		}
	}

	// 4th attempt should be blocked with ErrRateLimited
	_, err = apiKeys.Authenticate(ctx, "gma_bad_key_attempt", apikeys.WithIPAddress(ipAttacker))
	if !errors.Is(err, apikeys.ErrRateLimited) {
		t.Fatalf("attempt 4: expected ErrRateLimited, got %v", err)
	}

	// Legitimate client from different IP creates and authenticates successfully
	res, err := apiKeys.Create(ctx, apikeys.CreateInput{Name: "Legit Client"})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	authRes, err := apiKeys.Authenticate(ctx, res.RawKey, apikeys.WithIPAddress("198.51.100.2"))
	if err != nil {
		t.Fatalf("different IP should not be blocked, got: %v", err)
	}
	if authRes.Key.ID != res.Key.ID {
		t.Errorf("unexpected key ID: %s", authRes.Key.ID)
	}
}

func TestSecurity_NoPlaintextExposureInModels(t *testing.T) {
	ctx := context.Background()
	_, apiKeys, _ := setupTestAuth(t)

	res, err := apiKeys.Create(ctx, apikeys.CreateInput{Name: "Sensitive Key"})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// 1. Check struct serialization
	bytes, err := json.Marshal(res.Key)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	serialized := string(bytes)

	if strings.Contains(serialized, res.RawKey) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: raw key found in JSON serialization of APIKey")
	}

	// 2. Secret entropy check
	if len(res.RawKey) < 32 {
		t.Fatalf("raw key too short, insufficient entropy: length=%d", len(res.RawKey))
	}
}

func TestSecurity_ConcurrentAuthenticationsAndRotations(t *testing.T) {
	ctx := context.Background()
	_, apiKeys, _ := setupTestAuth(t)

	res, err := apiKeys.Create(ctx, apikeys.CreateInput{Name: "High Concurrency Key"})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	var wg sync.WaitGroup
	workers := 20
	iterations := 25

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, err := apiKeys.Authenticate(ctx, res.RawKey,
					apikeys.WithIPAddress("10.0.0.1"),
					apikeys.WithUserAgent("benchmark"),
				)
				if err != nil && !errors.Is(err, apikeys.ErrKeyRevoked) {
					t.Errorf("worker %d iteration %d unexpected error: %v", workerID, i, err)
				}
			}
		}(w)
	}

	// Concurrently rotate the key after a small delay
	go func() {
		time.Sleep(5 * time.Millisecond)
		_, _ = apiKeys.Rotate(ctx, res.Key.ID, apikeys.WithGracePeriod(50*time.Millisecond))
	}()

	wg.Wait()
}
