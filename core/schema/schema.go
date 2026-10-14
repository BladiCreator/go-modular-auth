// Package schema defines the declarative, schema-driven data model for GoModularAuth.
//
// In GoModularAuth, persistent schemas are defined centrally and can be extended
// by plugin modules (e.g. adding two_factor_enabled to users, or registering new
// models like passkeys or organizations). Database adapters consume the compiled
// Schema to execute queries, map fields, and generate or execute database migrations.
package schema

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

var (
	// ErrModelNotFound indicates the requested model does not exist in the schema.
	ErrModelNotFound = errors.New("schema: model not found")
	// ErrModelExists indicates a model with the same name is already registered.
	ErrModelExists = errors.New("schema: model already exists")
	// ErrFieldExists indicates a field already exists in the model.
	ErrFieldExists = errors.New("schema: field already exists")
	// ErrInvalidField indicates a field definition is invalid.
	ErrInvalidField = errors.New("schema: invalid field")
	// ErrInvalidModel indicates a model definition is invalid.
	ErrInvalidModel = errors.New("schema: invalid model")
	// ErrInvalidReference indicates a foreign key reference targets a nonexistent model or field.
	ErrInvalidReference = errors.New("schema: invalid foreign key reference")
)

// DataType represents the canonical data types supported across all storage engines.
type DataType string

const (
	TypeString  DataType = "string"
	TypeInt64   DataType = "int64"
	TypeFloat64 DataType = "float64"
	TypeBool    DataType = "bool"
	TypeTime    DataType = "time"
	TypeBytes   DataType = "bytes"
	TypeJSON    DataType = "json"
)

// IsValid reports whether dt is one of the supported canonical data types.
func (dt DataType) IsValid() bool {
	switch dt {
	case TypeString, TypeInt64, TypeFloat64, TypeBool, TypeTime, TypeBytes, TypeJSON:
		return true
	default:
		return false
	}
}

// Reference defines a relational foreign key constraint to another model.
type Reference struct {
	Model    string
	Field    string
	OnDelete string // e.g. "CASCADE", "SET NULL", "RESTRICT"
}

// Field describes a single column or property within a Model.
type Field struct {
	Name       string
	DBName     string // Column name in database; defaults to Name if empty
	Type       DataType
	Required   bool
	Unique     bool
	Indexed    bool
	Default    any
	References *Reference
}

// EffectiveDBName returns the database column name, defaulting to Name if DBName is empty.
func (f Field) EffectiveDBName() string {
	if f.DBName != "" {
		return f.DBName
	}
	return f.Name
}

// Index describes a single or composite index on a model.
type Index struct {
	Name   string
	Fields []string
	Unique bool
}

// Model represents a domain entity table or collection in the storage engine.
type Model struct {
	Name       string
	TableName  string
	PrimaryKey string
	Fields     map[string]Field
	Indexes    []Index
}

// NewModel creates an empty Model initialized with the given name, table name, and primary key.
func NewModel(name, tableName, primaryKey string) *Model {
	return &Model{
		Name:       name,
		TableName:  tableName,
		PrimaryKey: primaryKey,
		Fields:     make(map[string]Field),
		Indexes:    make([]Index, 0),
	}
}

// AddField registers a field into the model, returning an error if a field with the same name exists.
func (m *Model) AddField(f Field) error {
	if f.Name == "" {
		return fmt.Errorf("%w: field name cannot be empty", ErrInvalidField)
	}
	if !f.Type.IsValid() {
		return fmt.Errorf("%w: unsupported data type %q for field %q", ErrInvalidField, f.Type, f.Name)
	}
	if _, exists := m.Fields[f.Name]; exists {
		return fmt.Errorf("%w: %q in model %q", ErrFieldExists, f.Name, m.Name)
	}
	m.Fields[f.Name] = f
	return nil
}

// GetField retrieves a field by name.
func (m *Model) GetField(name string) (Field, bool) {
	f, ok := m.Fields[name]
	return f, ok
}

// Clone creates a deep copy of the model.
func (m *Model) Clone() *Model {
	cloned := &Model{
		Name:       m.Name,
		TableName:  m.TableName,
		PrimaryKey: m.PrimaryKey,
		Fields:     make(map[string]Field, len(m.Fields)),
		Indexes:    make([]Index, len(m.Indexes)),
	}
	for k, v := range m.Fields {
		cloned.Fields[k] = v
	}
	copy(cloned.Indexes, m.Indexes)
	return cloned
}

// Schema aggregates all Models in the authentication engine and manages extensions.
type Schema struct {
	mu     sync.RWMutex
	models map[string]*Model
}

// New creates an empty Schema.
func New() *Schema {
	return &Schema{
		models: make(map[string]*Model),
	}
}

// AddModel registers a model into the schema.
func (s *Schema) AddModel(m *Model) error {
	if m == nil {
		return fmt.Errorf("%w: model cannot be nil", ErrInvalidModel)
	}
	if m.Name == "" {
		return fmt.Errorf("%w: model name cannot be empty", ErrInvalidModel)
	}
	if m.TableName == "" {
		m.TableName = strings.ToLower(m.Name)
	}
	if m.PrimaryKey == "" {
		return fmt.Errorf("%w: model %q must define a PrimaryKey", ErrInvalidModel, m.Name)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.models[m.Name]; exists {
		return fmt.Errorf("%w: %q", ErrModelExists, m.Name)
	}

	s.models[m.Name] = m.Clone()
	return nil
}

// GetModel retrieves a model by name from the schema.
func (s *Schema) GetModel(name string) (*Model, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, ok := s.models[name]
	if !ok {
		return nil, false
	}
	return m.Clone(), true
}

// Models returns a cloned map of all registered models.
func (s *Schema) Models() map[string]*Model {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make(map[string]*Model, len(s.models))
	for k, v := range s.models {
		res[k] = v.Clone()
	}
	return res
}

// ExtendModel allows plugins to inject new fields into an existing model.
func (s *Schema) ExtendModel(modelName string, fields ...Field) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.models[modelName]
	if !ok {
		return fmt.Errorf("%w: %q", ErrModelNotFound, modelName)
	}

	for _, f := range fields {
		if err := m.AddField(f); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks the overall integrity of the schema, ensuring all primary keys,
// field data types, indexes, and foreign key references are consistent.
func (s *Schema) Validate() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for modelName, m := range s.models {
		if m.PrimaryKey == "" {
			return fmt.Errorf("%w: model %q missing PrimaryKey", ErrInvalidModel, modelName)
		}
		pkField, pkFound := m.Fields[m.PrimaryKey]
		if !pkFound {
			return fmt.Errorf("%w: primary key %q not found in fields of model %q", ErrInvalidModel, m.PrimaryKey, modelName)
		}
		if !pkField.Required {
			return fmt.Errorf("%w: primary key %q of model %q must be Required", ErrInvalidModel, m.PrimaryKey, modelName)
		}

		// Verify fields and foreign key references
		for fieldName, field := range m.Fields {
			if !field.Type.IsValid() {
				return fmt.Errorf("%w: invalid type %q on field %q of model %q", ErrInvalidField, field.Type, fieldName, modelName)
			}
			if ref := field.References; ref != nil {
				targetModel, targetFound := s.models[ref.Model]
				if !targetFound {
					return fmt.Errorf("%w: model %q field %q references nonexistent model %q",
						ErrInvalidReference, modelName, fieldName, ref.Model)
				}
				if _, targetFieldFound := targetModel.Fields[ref.Field]; !targetFieldFound {
					return fmt.Errorf("%w: model %q field %q references nonexistent field %q in model %q",
						ErrInvalidReference, modelName, fieldName, ref.Field, ref.Model)
				}
			}
		}

		// Verify indexes
		for _, idx := range m.Indexes {
			for _, fName := range idx.Fields {
				if _, ok := m.Fields[fName]; !ok {
					return fmt.Errorf("%w: index %q on model %q references nonexistent field %q",
						ErrInvalidModel, idx.Name, modelName, fName)
				}
			}
		}
	}

	return nil
}

// Clone returns a deep copy of the Schema.
func (s *Schema) Clone() *Schema {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cloned := New()
	for _, m := range s.models {
		_ = cloned.AddModel(m.Clone())
	}
	return cloned
}
