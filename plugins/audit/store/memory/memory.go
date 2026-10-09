// Package memory provides an in-memory implementation of the audit Store interface.
package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/BladiCreator/go-modular-auth-audit/store"
)

// Store implements store.Store using thread-safe in-memory collections.
// Ideal for unit testing, integration tests, and local development.
type Store struct {
	mu      sync.RWMutex
	records []*store.AuditRecord
	byID    map[string]*store.AuditRecord
}

var _ store.Store = (*Store)(nil)

// New creates a new in-memory audit store.
func New() *Store {
	return &Store{
		records: make([]*store.AuditRecord, 0),
		byID:    make(map[string]*store.AuditRecord),
	}
}

// Record persists a single audit log entry in memory.
func (s *Store) Record(ctx context.Context, record *store.AuditRecord) error {
	if record == nil {
		return store.ErrNilRecord
	}

	if err := record.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cloned := cloneRecord(record)
	s.records = append(s.records, cloned)
	s.byID[cloned.ID] = cloned

	return nil
}

// RecordBatch persists multiple audit records atomically in memory.
func (s *Store) RecordBatch(ctx context.Context, records []*store.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, record := range records {
		if record == nil {
			return store.ErrNilRecord
		}
		if err := record.Validate(); err != nil {
			return err
		}
		cloned := cloneRecord(record)
		s.records = append(s.records, cloned)
		s.byID[cloned.ID] = cloned
	}

	return nil
}

// GetByID retrieves a single audit record by its identifier.
func (s *Store) GetByID(ctx context.Context, id string) (*store.AuditRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneRecord(rec), nil
}

// Query filters and paginates in-memory audit records according to ListFilter.
func (s *Store) Query(ctx context.Context, filter store.ListFilter) ([]*store.AuditRecord, int, error) {
	filter.Normalize()

	s.mu.RLock()
	defer s.mu.RUnlock()

	var matched []*store.AuditRecord

	for _, rec := range s.records {
		if filter.ActorSubject != "" && rec.ActorSubject != filter.ActorSubject {
			continue
		}
		if filter.ActorType != "" && rec.ActorType != filter.ActorType {
			continue
		}
		if filter.TargetType != "" && rec.TargetType != filter.TargetType {
			continue
		}
		if filter.TargetID != "" && rec.TargetID != filter.TargetID {
			continue
		}
		if filter.Event != "" && rec.Event != filter.Event {
			continue
		}
		if filter.Outcome != "" && rec.Outcome != filter.Outcome {
			continue
		}
		if filter.OrganizationID != "" && rec.OrganizationID != filter.OrganizationID {
			continue
		}
		if !filter.Since.IsZero() && rec.Timestamp.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && rec.Timestamp.After(filter.Until) {
			continue
		}

		matched = append(matched, cloneRecord(rec))
	}

	total := len(matched)

	// Sort matching records descending by timestamp (newest first)
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Timestamp.After(matched[j].Timestamp)
	})

	if filter.Offset >= total {
		return []*store.AuditRecord{}, total, nil
	}

	end := filter.Offset + filter.Limit
	if end > total {
		end = total
	}

	return matched[filter.Offset:end], total, nil
}

// Reset clears all in-memory audit records (useful between tests).
func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = make([]*store.AuditRecord, 0)
	s.byID = make(map[string]*store.AuditRecord)
}

func cloneRecord(r *store.AuditRecord) *store.AuditRecord {
	if r == nil {
		return nil
	}
	cp := *r
	if r.Metadata != nil {
		cp.Metadata = make(map[string]any, len(r.Metadata))
		for k, v := range r.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}
