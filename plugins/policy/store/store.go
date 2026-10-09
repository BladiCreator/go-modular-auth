package store

import (
	"context"
	"time"
)

// PolicyRecord represents a persisted policy metadata entry.
type PolicyRecord struct {
	ID          string    `json:"id"`
	Description string    `json:"description,omitempty"`
	Combinator  string    `json:"combinator,omitempty"` // e.g. "deny_overrides", "all_of", "any_of"
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Store defines the persistence contract for policy metadata.
type Store interface {
	SavePolicyRecord(ctx context.Context, r *PolicyRecord) error
	GetPolicyRecord(ctx context.Context, id string) (*PolicyRecord, error)
	ListPolicyRecords(ctx context.Context) ([]*PolicyRecord, error)
	DeletePolicyRecord(ctx context.Context, id string) error
}
