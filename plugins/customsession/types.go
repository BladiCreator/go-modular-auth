// Package customsession provides dynamic session payload transformation and dynamic additional fields management.
package customsession

import (
	"context"
	"net/http"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// TransformSessionFunc is the callback signature for transforming and enriching session response data dynamically per request.
type TransformSessionFunc func(ctx context.Context, sessionData *dto.SessionData, req *http.Request) (any, error)

// FieldType defines the supported data types for dynamic additional fields.
type FieldType string

const (
	// FieldTypeString represents a text/string property.
	FieldTypeString FieldType = "string"
	// FieldTypeNumber represents a numeric (int, float) property.
	FieldTypeNumber FieldType = "number"
	// FieldTypeBoolean represents a boolean property.
	FieldTypeBoolean FieldType = "boolean"
	// FieldTypeDate represents a date/time property.
	FieldTypeDate FieldType = "date"
	// FieldTypeObject represents a complex object/map property.
	FieldTypeObject FieldType = "object"
)

// AdditionalFieldDefinition defines metadata, validation, and defaults for dynamic fields on User or Session entities.
type AdditionalFieldDefinition struct {
	Name         string             `json:"name"`
	Type         FieldType          `json:"type"`
	Required     bool               `json:"required"`
	DefaultValue any                `json:"defaultValue,omitempty"`
	Validator    func(val any) bool `json:"-"`
}

// CustomSessionData is the standard response container holding user, session, and dynamic extra payload fields.
type CustomSessionData struct {
	User    *entity.User    `json:"user"`
	Session *entity.Session `json:"session"`
	plugin.ExtraContainer
}

// AdditionalFieldsConfig holds field definitions for user and session models.
type AdditionalFieldsConfig struct {
	UserFields    []AdditionalFieldDefinition `json:"userFields"`
	SessionFields []AdditionalFieldDefinition `json:"sessionFields"`
}
