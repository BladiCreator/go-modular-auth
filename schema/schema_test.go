package schema_test

import (
	"errors"
	"testing"

	"github.com/BladiCreator/go-modular-auth/schema"
)

func TestDefaultCoreSchema(t *testing.T) {
	s, err := schema.DefaultCoreSchema()
	if err != nil {
		t.Fatalf("DefaultCoreSchema() error = %v", err)
	}

	expectedModels := []string{
		schema.ModelUsers,
		schema.ModelAccounts,
		schema.ModelCredentials,
		schema.ModelSessions,
		schema.ModelVerifications,
	}

	models := s.Models()
	for _, expected := range expectedModels {
		if _, ok := models[expected]; !ok {
			t.Errorf("expected model %q was not found in schema", expected)
		}
	}
}

func TestExtendModel(t *testing.T) {
	s, err := schema.DefaultCoreSchema()
	if err != nil {
		t.Fatalf("DefaultCoreSchema() error = %v", err)
	}

	// Plugins extend users with 2FA and role
	err = s.ExtendModel(schema.ModelUsers,
		schema.Field{Name: "two_factor_enabled", DBName: "two_factor_enabled", Type: schema.TypeBool, Default: false},
		schema.Field{Name: "role", DBName: "role", Type: schema.TypeString, Default: "user"},
	)
	if err != nil {
		t.Fatalf("ExtendModel failed: %v", err)
	}

	userModel, ok := s.GetModel(schema.ModelUsers)
	if !ok {
		t.Fatal("users model not found")
	}

	if f, found := userModel.GetField("two_factor_enabled"); !found || f.Type != schema.TypeBool {
		t.Errorf("field two_factor_enabled was not properly added: %+v", f)
	}

	if f, found := userModel.GetField("role"); !found || f.Type != schema.TypeString {
		t.Errorf("field role was not properly added: %+v", f)
	}

	// Test collision detection: trying to add duplicate field
	err = s.ExtendModel(schema.ModelUsers, schema.Field{Name: "email", Type: schema.TypeString})
	if !errors.Is(err, schema.ErrFieldExists) {
		t.Errorf("expected ErrFieldExists on duplicate field, got: %v", err)
	}

	// Test nonexistent model
	err = s.ExtendModel("nonexistent", schema.Field{Name: "test", Type: schema.TypeString})
	if !errors.Is(err, schema.ErrModelNotFound) {
		t.Errorf("expected ErrModelNotFound, got: %v", err)
	}
}

func TestSchemaValidation(t *testing.T) {
	t.Run("valid custom model with reference", func(t *testing.T) {
		s, err := schema.DefaultCoreSchema()
		if err != nil {
			t.Fatalf("failed to get default schema: %v", err)
		}

		customModel := schema.NewModel("two_factors", "two_factors", "id")
		_ = customModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
		_ = customModel.AddField(schema.Field{
			Name:     "user_id",
			Type:     schema.TypeString,
			Required: true,
			References: &schema.Reference{
				Model:    schema.ModelUsers,
				Field:    "id",
				OnDelete: "CASCADE",
			},
		})
		_ = customModel.AddField(schema.Field{Name: "secret", Type: schema.TypeString, Required: true})

		if err := s.AddModel(customModel); err != nil {
			t.Fatalf("AddModel failed: %v", err)
		}

		if err := s.Validate(); err != nil {
			t.Fatalf("Validate failed on valid custom model: %v", err)
		}
	})

	t.Run("reference to nonexistent model fails", func(t *testing.T) {
		s := schema.New()
		m := schema.NewModel("items", "items", "id")
		_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
		_ = m.AddField(schema.Field{
			Name: "user_id",
			Type: schema.TypeString,
			References: &schema.Reference{
				Model: "nonexistent",
				Field: "id",
			},
		})
		_ = s.AddModel(m)

		err := s.Validate()
		if !errors.Is(err, schema.ErrInvalidReference) {
			t.Errorf("expected ErrInvalidReference, got: %v", err)
		}
	})

	t.Run("missing primary key fails validation", func(t *testing.T) {
		s := schema.New()
		m := schema.NewModel("items", "items", "id")
		// Not adding "id" field
		_ = s.AddModel(m)

		err := s.Validate()
		if !errors.Is(err, schema.ErrInvalidModel) {
			t.Errorf("expected ErrInvalidModel for missing PK field, got: %v", err)
		}
	})
}

func TestCloneIsolation(t *testing.T) {
	s, _ := schema.DefaultCoreSchema()
	cloned := s.Clone()

	_ = cloned.ExtendModel(schema.ModelUsers, schema.Field{Name: "extra", Type: schema.TypeString})

	origUser, _ := s.GetModel(schema.ModelUsers)
	if _, found := origUser.GetField("extra"); found {
		t.Error("modifying cloned schema mutated the original schema")
	}
}
