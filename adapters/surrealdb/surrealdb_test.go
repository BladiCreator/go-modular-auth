package surrealdb_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/adapters/surrealdb"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/surrealdb/surrealdb.go/pkg/connection"
)

func TestInterfaceCompliance(t *testing.T) {
	var _ adapter.Adapter = (*surrealdb.Adapter)(nil)
}

func TestAdapterInstantiation(t *testing.T) {
	ad := surrealdb.New(nil)
	if ad == nil {
		t.Fatal("expected non-nil adapter")
	}

	// Schema registration should succeed even before DB is connected
	s := schema.New()
	m := schema.NewModel("user", "user", "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "email", Type: schema.TypeString})
	_ = s.AddModel(m)

	if err := ad.RegisterSchema(context.Background(), s); err != nil {
		t.Fatalf("unexpected RegisterSchema error: %v", err)
	}
}

func TestAuthEngineIntegrationWithSurrealDBAdapter(t *testing.T) {
	ad := surrealdb.New(nil)
	engine, err := auth.New(auth.Config{
		Adapter: ad,
	})
	if err != nil {
		t.Fatalf("auth.New with surrealdb adapter failed: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestQueryWhereBuilder(t *testing.T) {
	q := adapter.Query{
		Model: "user",
		Where: []adapter.Condition{
			adapter.Eq("email", "test@example.com"),
			adapter.Eq("id", "usr_123"),
			adapter.Gt("age", 18),
			adapter.In("status", "active", "pending"),
			adapter.IsNull("deleted_at"),
			adapter.IsNotNull("created_at"),
		},
	}

	ad := surrealdb.New(nil)
	// FindMany on a nil db will fail cleanly when attempting query execution,
	// but lets us check that the syntax building doesn't panic.
	_, err := ad.FindMany(context.Background(), q)
	if err == nil {
		t.Fatal("expected error with nil db")
	}
	if !strings.Contains(err.Error(), "database connection is nil") {
		t.Fatalf("expected nil db error, got: %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{
			name:     "already exists message",
			input:    errors.New("Database record `user:usr_1` already exists"),
			expected: adapter.ErrConflict,
		},
		{
			name:     "unique index violation",
			input:    errors.New("There was a problem with unique index `idx_user_email`"),
			expected: adapter.ErrConflict,
		},
		{
			name:     "not found message",
			input:    errors.New("Record not found"),
			expected: adapter.ErrNotFound,
		},
		{
			name:     "connection KindAlreadyExists",
			input:    &connection.ServerError{Kind: connection.KindAlreadyExists},
			expected: adapter.ErrConflict,
		},
		{
			name:     "connection KindNotFound",
			input:    &connection.ServerError{Kind: connection.KindNotFound},
			expected: adapter.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := surrealdb.MapError(tt.input)
			if !errors.Is(got, tt.expected) {
				t.Errorf("MapError(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestModelDDLGeneration(t *testing.T) {
	ad := surrealdb.New(nil)
	s := schema.New()
	m := schema.NewModel("users", "users", "id")
	_ = m.AddField(schema.Field{
		Name:     "id",
		Type:     schema.TypeString,
		Required: true,
	})
	_ = m.AddField(schema.Field{
		Name:     "email",
		Type:     schema.TypeString,
		Required: true,
		Unique:   true,
	})
	_ = m.AddField(schema.Field{
		Name: "is_active",
		Type: schema.TypeBool,
	})
	_ = m.AddField(schema.Field{
		Name: "metadata",
		Type: schema.TypeJSON,
	})
	_ = s.AddModel(m)

	if err := ad.RegisterSchema(context.Background(), s); err != nil {
		t.Fatalf("RegisterSchema failed: %v", err)
	}

	// Migrate without DB connection should fail cleanly when attempting execution
	err := ad.Migrate(context.Background())
	if err == nil {
		t.Fatal("expected error attempting to execute DDL with nil DB")
	}
}
