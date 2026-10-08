package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates the requested metadata record was not found in the store.
	ErrNotFound = errors.New("multisession store: record not found")
)

// DeviceRecord contains persistent device identification details.
type DeviceRecord struct {
	Name      string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"`
	OS        string `json:"os,omitempty"`
	Browser   string `json:"browser,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
}

// MetadataRecord is the persistent representation of session metadata.
type MetadataRecord struct {
	SessionID string            `json:"session_id"`
	UserID    string            `json:"user_id"`
	Device    DeviceRecord      `json:"device"`
	Custom    map[string]string `json:"custom,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Store is the persistence contract for session metadata.
type Store interface {
	// Save persists or updates the metadata record for a session.
	Save(ctx context.Context, rec *MetadataRecord) error

	// Get retrieves the metadata record for the given session ID.
	// Returns ErrNotFound if the record does not exist.
	Get(ctx context.Context, sessionID string) (*MetadataRecord, error)

	// Delete removes the metadata record for a session ID.
	Delete(ctx context.Context, sessionID string) error

	// DeleteBySessionIDs bulk removes metadata records for the provided session IDs.
	DeleteBySessionIDs(ctx context.Context, sessionIDs []string) error
}
