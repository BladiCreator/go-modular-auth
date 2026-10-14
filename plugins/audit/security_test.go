package audit_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	audit "github.com/BladiCreator/go-modular-auth/plugins/audit"
)

func TestSecurity_Sanitizer_NeverStoresSecrets(t *testing.T) {
	sensitivePayload := map[string]any{
		"user_id":          "user_safe_123",
		"action":           "user_login",
		"password":         "SuperSecretPassword123!",
		"user_password":    "AnotherPlainPassword",
		"raw_passwd":       "PlainPass",
		"access_token":     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy",
		"refresh_token":    "rt_9876543210abcdef",
		"bearer_token":     "bearer_secret_token",
		"session_token":    "sess_tok_abcdef",
		"token_list":       "raw_token_data",
		"otp":              "654321",
		"totp_code":        "123456",
		"user_code":        "WDJB-9988",
		"device_code":      "devcode_super_secret",
		"client_secret":    "cs_topsecret_9988",
		"private_key":      "-----BEGIN RSA PRIVATE KEY-----...",
		"password_hash":    "$2a$12$e8Y6l123456789...",
		"salt":             "random_salt_bytes",
		"authorization":    "Bearer sensitive_token",
		"credentials_bag": map[string]any{
			"raw_blob": "super_secret_blob",
		},
		"nested_profile": map[string]any{
			"nested_password": "nested_secret_val",
			"nested_otp":      "999888",
			"safe_nested":     "hello_world",
		},
		"device_items": []any{
			"raw_device",
			map[string]any{
				"code":      "112233",
				"safe_name": "device_item",
			},
		},
	}

	sanitized := audit.SanitizeMetadata(sensitivePayload)

	// Invariant checks: all sensitive keys must be redacted
	forbiddenKeys := []string{
		"password", "user_password", "raw_passwd",
		"access_token", "refresh_token", "bearer_token", "session_token", "token_list",
		"otp", "totp_code", "user_code", "device_code",
		"client_secret", "private_key", "password_hash", "salt",
		"authorization", "credentials_bag",
	}

	for _, k := range forbiddenKeys {
		val, exists := sanitized[k]
		if !exists {
			t.Errorf("expected key %s to exist in sanitized map, but was missing", k)
		}
		if val != "[REDACTED]" {
			t.Errorf("CRITICAL SECURITY LEAK: key %s was not redacted! Value: %v", k, val)
		}
	}

	// Safe keys should be retained
	if sanitized["user_id"] != "user_safe_123" {
		t.Errorf("expected safe field user_id to be preserved, got %v", sanitized["user_id"])
	}
	if sanitized["action"] != "user_login" {
		t.Errorf("expected safe field action to be preserved, got %v", sanitized["action"])
	}

	// Nested object with safe parent key should recurse and sanitize child properties
	nested, ok := sanitized["nested_profile"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested_profile to be map[string]any, got %T", sanitized["nested_profile"])
	}
	if nested["nested_password"] != "[REDACTED]" {
		t.Errorf("nested password was not redacted")
	}
	if nested["nested_otp"] != "[REDACTED]" {
		t.Errorf("nested otp was not redacted")
	}
	if nested["safe_nested"] != "hello_world" {
		t.Errorf("nested safe value altered")
	}

	// Slice elements with safe parent key should recurse and sanitize items
	sliceItems, ok := sanitized["device_items"].([]any)
	if !ok {
		t.Fatalf("expected device_items to be []any, got %T", sanitized["device_items"])
	}
	sliceMap, ok := sliceItems[1].(map[string]any)
	if !ok {
		t.Fatalf("expected slice map element to be map[string]any, got %T", sliceItems[1])
	}
	if sliceMap["code"] != "[REDACTED]" {
		t.Errorf("slice item code was not redacted")
	}
	if sliceMap["safe_name"] != "device_item" {
		t.Errorf("slice safe item altered")
	}
}

func TestSecurity_Concurrency_ThreadSafeAudit(t *testing.T) {
	ctx := context.Background()
	_, audCap := setupTestAuth(t)

	var wg sync.WaitGroup
	workers := 20
	iterations := 50

	// Concurrent writes
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = audCap.Record(ctx, &audit.AuditRecord{
					Event:        "audit.concurrency.test",
					Action:       "test_action",
					ActorSubject: fmt.Sprintf("worker_%d", workerID),
					ActorType:    string(auth.PrincipalUser),
					TargetType:   "test_resource",
					TargetID:     fmt.Sprintf("res_%d_%d", workerID, j),
					Outcome:      audit.OutcomeSuccess,
					Metadata: map[string]any{
						"worker": workerID,
						"index":  j,
					},
				})
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for j := 0; j < iterations/2; j++ {
				_, _ = audCap.Query(ctx, audit.ListFilter{
					Event: "audit.concurrency.test",
					Limit: 10,
				})
				time.Sleep(2 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()

	totalExpected := workers * iterations
	res, err := audCap.Query(ctx, audit.ListFilter{
		Event: "audit.concurrency.test",
		Limit: 1000,
	})
	if err != nil {
		t.Fatalf("Query after concurrency test failed: %v", err)
	}
	if res.Total != totalExpected {
		t.Fatalf("expected total %d records, got %d", totalExpected, res.Total)
	}
}
