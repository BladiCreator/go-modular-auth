package sdk_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

type DummyRecord struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
}

type dummyPlugin struct {
	repo *sdk.Repository[DummyRecord]
}

func (p *dummyPlugin) ID() string { return "dummy" }

func (p *dummyPlugin) RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel("dummies", "dummies", "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "secret", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	return s.AddModel(m)
}

func (p *dummyPlugin) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	p.repo = sdk.Model[DummyRecord](ctx, "dummies")
	return nil
}

func TestSDK_GenericRepository(t *testing.T) {
	ctx := context.Background()
	memAdapter := adaptermem.New()
	dp := &dummyPlugin{}

	_, err := auth.New(auth.Config{
		Adapter: memAdapter,
		Plugins: []auth.PluginModule{dp},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	if dp.repo == nil {
		t.Fatal("expected repo to be initialized")
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	rec := &DummyRecord{
		ID:        "rec_1",
		UserID:    "usr_1",
		Secret:    "super_secret",
		CreatedAt: now,
	}

	// 1. Create
	if err := dp.repo.Create(ctx, rec); err != nil {
		t.Fatalf("repo.Create failed: %v", err)
	}

	// 2. FindOne
	found, err := dp.repo.FindOne(ctx, adapter.Eq("id", "rec_1"))
	if err != nil {
		t.Fatalf("repo.FindOne failed: %v", err)
	}
	if found.Secret != "super_secret" {
		t.Errorf("expected super_secret, got %v", found.Secret)
	}

	// 3. FindMany
	all, err := dp.repo.FindMany(ctx, adapter.Query{
		Where: []adapter.Condition{adapter.Eq("user_id", "usr_1")},
	})
	if err != nil {
		t.Fatalf("repo.FindMany failed: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 record, got %d", len(all))
	}

	// 4. Count
	count, err := dp.repo.Count(ctx, adapter.Eq("user_id", "usr_1"))
	if err != nil {
		t.Fatalf("repo.Count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	// 5. Delete
	deleted, err := dp.repo.Delete(ctx, adapter.Eq("id", "rec_1"))
	if err != nil {
		t.Fatalf("repo.Delete failed: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}
}
