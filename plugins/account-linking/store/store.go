// Package store defines the persistence contract for Account Linking tickets and operations.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates that the requested linking ticket was not found.
	ErrNotFound = errors.New("account-linking store: record not found")

	// ErrConflict indicates a uniqueness violation (e.g. token hash collision).
	ErrConflict = errors.New("account-linking store: record conflict")

	// ErrTicketConsumed indicates that the linking ticket has already been used.
	ErrTicketConsumed = errors.New("account-linking store: ticket already consumed")
)

// LinkingTicket holds ephemeral single-use state for two-step account linking ceremonies.
type LinkingTicket struct {
	ID             string            `json:"id"`
	TokenHash      string            `json:"token_hash"`
	UserID         string            `json:"user_id"`
	TargetProvider string            `json:"target_provider,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	ConsumedAt     *time.Time        `json:"consumed_at,omitempty"`
	ExpiresAt      time.Time         `json:"expires_at"`
	CreatedAt      time.Time         `json:"created_at"`
}

// Expired reports whether the ticket is expired relative to the given time.
func (t *LinkingTicket) Expired(now time.Time) bool {
	return t != nil && !now.Before(t.ExpiresAt)
}

// IsConsumed reports whether the ticket has already been used.
func (t *LinkingTicket) IsConsumed() bool {
	return t != nil && t.ConsumedAt != nil
}

// Store defines the storage operations required for Account Linking tickets.
type Store interface {
	// SaveTicket persists a new linking ticket.
	SaveTicket(ctx context.Context, ticket *LinkingTicket) error

	// GetTicketByHash retrieves a ticket by its token hash without consuming it.
	GetTicketByHash(ctx context.Context, tokenHash string) (*LinkingTicket, error)

	// ConsumeTicket atomically marks a ticket as consumed at the given time.
	// If the ticket was already consumed, it returns ErrTicketConsumed.
	ConsumeTicket(ctx context.Context, tokenHash string, now time.Time) (*LinkingTicket, error)

	// DeleteTicket permanently removes a ticket by its ID.
	DeleteTicket(ctx context.Context, id string) error

	// PurgeExpiredTickets removes all tickets expired before the given cutoff timestamp.
	PurgeExpiredTickets(ctx context.Context, before time.Time) (int, error)
}
