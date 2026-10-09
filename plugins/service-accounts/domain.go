package serviceaccounts

import (
	"errors"
	"time"
)

var (
	ErrNotFound       = errors.New("serviceaccounts: not found")
	ErrInactive       = errors.New("serviceaccounts: account is inactive")
	ErrInvalidSecret  = errors.New("serviceaccounts: invalid credentials")
	ErrInvalidName    = errors.New("serviceaccounts: name is required")
	ErrInvalidOwnerID = errors.New("serviceaccounts: owner_id is required")
)

// ServiceAccount represents a machine-to-machine (M2M) identity.
type ServiceAccount struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	OwnerID     string    `json:"owner_id"`
	Scopes      []string  `json:"scopes"`
	SecretHash  string    `json:"-"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	OwnerID     string   `json:"owner_id"`
	Scopes      []string `json:"scopes,omitempty"`
}
