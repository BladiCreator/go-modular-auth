package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/adapter/memory"
	"github.com/BladiCreator/go-modular-auth/schema"
)

func setupTestAdapter(t *testing.T) (*memory.Adapter, *schema.Schema) {
	s, err := schema.DefaultCoreSchema()
	if err != nil {
		t.Fatalf("failed to build default schema: %v", err)
	}

	ad := memory.New()
	if err := ad.RegisterSchema(context.Background(), s); err != nil {
		t.Fatalf("failed to register schema: %v", err)
	}

	return ad, s
}

func TestMemoryAdapter_CRUD(t *testing.T) {
	ctx := context.Background()
	ad, _ := setupTestAdapter(t)

	now := time.Now().UTC()
	userRow := map[string]any{
		"id":             "usr_123",
		"email":          "alice@example.com",
		"email_verified": true,
		"created_at":     now,
		"updated_at":     now,
	}

	// 1. Create
	created, err := ad.Create(ctx, schema.ModelUsers, userRow)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if created["id"] != "usr_123" || created["email"] != "alice@example.com" {
		t.Errorf("unexpected created row: %+v", created)
	}

	// 2. FindOne
	found, err := ad.FindOne(ctx, schema.ModelUsers, []adapter.Condition{
		adapter.Eq("email", "alice@example.com"),
	})
	if err != nil {
		t.Fatalf("FindOne failed: %v", err)
	}
	if found["id"] != "usr_123" {
		t.Errorf("unexpected found row id: %v", found["id"])
	}

	// 3. Update
	updatedRows, err := ad.Update(ctx, schema.ModelUsers, []adapter.Condition{
		adapter.Eq("id", "usr_123"),
	}, map[string]any{
		"email": "alice_updated@example.com",
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updatedRows != 1 {
		t.Errorf("expected 1 updated row, got %d", updatedRows)
	}

	// Verify update
	foundUpdated, _ := ad.FindOne(ctx, schema.ModelUsers, []adapter.Condition{
		adapter.Eq("id", "usr_123"),
	})
	if foundUpdated["email"] != "alice_updated@example.com" {
		t.Errorf("expected updated email, got: %v", foundUpdated["email"])
	}

	// 4. Count
	count, err := ad.Count(ctx, schema.ModelUsers, []adapter.Condition{
		adapter.Eq("email_verified", true),
	})
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	// 5. Delete
	deleted, err := ad.Delete(ctx, schema.ModelUsers, []adapter.Condition{
		adapter.Eq("id", "usr_123"),
	})
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted row, got %d", deleted)
	}

	// Verify deleted
	_, err = ad.FindOne(ctx, schema.ModelUsers, []adapter.Condition{
		adapter.Eq("id", "usr_123"),
	})
	if !errors.Is(err, adapter.ErrNotFound) {
		t.Errorf("expected ErrNotFound after deletion, got %v", err)
	}
}

func TestMemoryAdapter_UniqueConstraints(t *testing.T) {
	ctx := context.Background()
	ad, _ := setupTestAdapter(t)

	now := time.Now().UTC()
	u1 := map[string]any{
		"id":         "usr_1",
		"email":      "duplicate@example.com",
		"created_at": now,
		"updated_at": now,
	}
	u2 := map[string]any{
		"id":         "usr_2",
		"email":      "duplicate@example.com", // Same email!
		"created_at": now,
		"updated_at": now,
	}

	if _, err := ad.Create(ctx, schema.ModelUsers, u1); err != nil {
		t.Fatalf("Create u1 failed: %v", err)
	}

	// Second insert should fail with ErrConflict
	_, err := ad.Create(ctx, schema.ModelUsers, u2)
	if !errors.Is(err, adapter.ErrConflict) {
		t.Errorf("expected ErrConflict on duplicate email, got: %v", err)
	}

	// Duplicate PK should fail
	u1DupPK := map[string]any{
		"id":         "usr_1",
		"email":      "other@example.com",
		"created_at": now,
		"updated_at": now,
	}
	_, err = ad.Create(ctx, schema.ModelUsers, u1DupPK)
	if !errors.Is(err, adapter.ErrConflict) {
		t.Errorf("expected ErrConflict on duplicate PK, got: %v", err)
	}
}

func TestMemoryAdapter_FindMany(t *testing.T) {
	ctx := context.Background()
	ad, _ := setupTestAdapter(t)

	for i := 1; i <= 5; i++ {
		_, _ = ad.Create(ctx, schema.ModelUsers, map[string]any{
			"id":         string(rune('a' + i)),
			"email":      string(rune('a'+i)) + "@example.com",
			"created_at": time.Now(),
			"updated_at": time.Now(),
		})
	}

	results, err := ad.FindMany(ctx, adapter.Query{
		Model:  schema.ModelUsers,
		Limit:  2,
		Offset: 1,
		SortBy: "email",
		Desc:   false,
	})
	if err != nil {
		t.Fatalf("FindMany failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results with pagination, got %d", len(results))
	}
}
