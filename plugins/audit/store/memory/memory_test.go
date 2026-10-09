package memory_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-audit/store"
	"github.com/BladiCreator/go-modular-auth-audit/store/memory"
)

func TestMemoryStore_CRUD_AndFilters(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	// 1. Error on nil record
	if err := s.Record(ctx, nil); !errors.Is(err, store.ErrNilRecord) {
		t.Fatalf("expected ErrNilRecord, got %v", err)
	}

	// 2. Batch insertion
	baseTime := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	var records []*store.AuditRecord
	for i := 0; i < 10; i++ {
		records = append(records, &store.AuditRecord{
			ID:             fmt.Sprintf("rec_%02d", i),
			Timestamp:      baseTime.Add(time.Duration(i) * time.Minute),
			Event:          "test.event",
			Action:         "test",
			ActorSubject:   fmt.Sprintf("user_%d", i%2),
			ActorType:      "user",
			TargetType:     "doc",
			TargetID:       fmt.Sprintf("doc_%d", i),
			Outcome:        store.OutcomeSuccess,
			OrganizationID: "org_1",
		})
	}

	if err := s.RecordBatch(ctx, records); err != nil {
		t.Fatalf("RecordBatch failed: %v", err)
	}

	// 3. GetByID
	rec, err := s.GetByID(ctx, "rec_03")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if rec.ID != "rec_03" {
		t.Fatalf("expected rec_03, got %s", rec.ID)
	}

	// 4. Missing ID
	_, err = s.GetByID(ctx, "rec_999")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// 5. Query filtering by ActorSubject
	matched, total, err := s.Query(ctx, store.ListFilter{
		ActorSubject: "user_0",
		Limit:        10,
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 5 || len(matched) != 5 {
		t.Fatalf("expected 5 matching records for user_0, got total=%d len=%d", total, len(matched))
	}

	// Verify order is newest first
	if matched[0].Timestamp.Before(matched[1].Timestamp) {
		t.Errorf("expected descending timestamp order")
	}

	// 6. Pagination
	p1, total, err := s.Query(ctx, store.ListFilter{
		Limit:  3,
		Offset: 0,
	})
	if err != nil || total != 10 || len(p1) != 3 {
		t.Fatalf("unexpected page 1 results: %v, total=%d, len=%d", err, total, len(p1))
	}

	p2, _, err := s.Query(ctx, store.ListFilter{
		Limit:  3,
		Offset: 3,
	})
	if err != nil || len(p2) != 3 {
		t.Fatalf("unexpected page 2 results")
	}

	if p1[0].ID == p2[0].ID {
		t.Fatalf("page 1 and page 2 overlap on first element")
	}

	// 7. Reset
	s.Reset()
	matchedAfterReset, totalAfterReset, _ := s.Query(ctx, store.ListFilter{})
	if totalAfterReset != 0 || len(matchedAfterReset) != 0 {
		t.Fatalf("expected empty store after reset")
	}
}
