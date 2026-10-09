package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

type service struct {
	ctx      *sdk.Context
	cfg      Config
	logger   *slog.Logger
	asyncCh  chan *AuditRecord
	wg       sync.WaitGroup
	stopOnce sync.Once
	stopCh   chan struct{}
}

var _ Audit = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	var logger *slog.Logger
	if ctx != nil {
		logger = ctx.Logger()
	} else {
		logger = slog.Default()
	}

	s := &service{
		ctx:    ctx,
		cfg:    cfg,
		logger: logger,
		stopCh: make(chan struct{}),
	}

	if cfg.AsyncWorkers > 0 {
		s.asyncCh = make(chan *AuditRecord, cfg.BufferSize)
		for i := 0; i < cfg.AsyncWorkers; i++ {
			s.wg.Add(1)
			go s.workerLoop()
		}
	}

	return s
}

// Record manually registers an explicit audit record, ensuring sanitization before persistence.
func (s *service) Record(ctx context.Context, record *AuditRecord) error {
	if record == nil {
		return ErrNilRecord
	}

	// Always sanitize incoming metadata before persisting
	if record.Metadata != nil {
		record.Metadata = SanitizeMetadata(record.Metadata)
	}

	if err := record.Validate(); err != nil {
		return err
	}

	if s.cfg.AsyncWorkers > 0 {
		select {
		case s.asyncCh <- record:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Buffer full fallback: record synchronously to guarantee zero lost audit logs
			s.logger.WarnContext(ctx, "audit: async buffer full, falling back to sync store")
			return s.cfg.Store.Record(ctx, record)
		}
	}

	return s.cfg.Store.Record(ctx, record)
}

// Query searches the audit log with customizable filtering and pagination criteria.
func (s *service) Query(ctx context.Context, filter ListFilter) (*ListResult, error) {
	filter.Normalize()
	records, total, err := s.cfg.Store.Query(ctx, filter)
	if err != nil {
		return nil, err
	}

	return &ListResult{
		Records: records,
		Total:   total,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
	}, nil
}

// GetByID retrieves a single audit entry by its unique identifier.
func (s *service) GetByID(ctx context.Context, id string) (*AuditRecord, error) {
	if strings.TrimSpace(id) == "" {
		return nil, ErrRecordNotFound
	}
	return s.cfg.Store.GetByID(ctx, id)
}

// QueryByActor returns audit entries performed by or associated with a specific actor subject.
func (s *service) QueryByActor(ctx context.Context, subject string, limit int) ([]*AuditRecord, error) {
	filter := ListFilter{
		ActorSubject: subject,
		Limit:        limit,
	}
	res, err := s.Query(ctx, filter)
	if err != nil {
		return nil, err
	}
	return res.Records, nil
}

// QueryByTarget returns audit entries affecting a specific target resource type and identifier.
func (s *service) QueryByTarget(ctx context.Context, targetType, targetID string, limit int) ([]*AuditRecord, error) {
	filter := ListFilter{
		TargetType: targetType,
		TargetID:   targetID,
		Limit:      limit,
	}
	res, err := s.Query(ctx, filter)
	if err != nil {
		return nil, err
	}
	return res.Records, nil
}

// QueryByOrganization returns paginated audit records scoped to a multi-tenant organization.
func (s *service) QueryByOrganization(ctx context.Context, orgID string, filter ListFilter) (*ListResult, error) {
	filter.OrganizationID = orgID
	return s.Query(ctx, filter)
}

// HandleEvent is the universal event consumer callback subscribed to GoModularAuth's EventBus.
func (s *service) HandleEvent(ctx context.Context, ev auth.Event) {
	if s.cfg.Filter != nil && !s.cfg.Filter(ev) {
		return
	}

	record := s.buildRecordFromEvent(ctx, ev)
	if err := s.Record(ctx, record); err != nil {
		s.logger.ErrorContext(ctx, "audit: failed to record audit event",
			"event", ev.Name,
			"error", err,
		)
	}
}

func (s *service) buildRecordFromEvent(ctx context.Context, ev auth.Event) *AuditRecord {
	ts := ev.Time
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	record := &AuditRecord{
		Timestamp:    ts,
		Event:        string(ev.Name),
		Action:       string(ev.Name),
		Outcome:      deriveOutcome(ev),
		Metadata:     SanitizeMetadata(ev.Payload),
		TargetType:   "resource",
		TargetID:     ev.Subject,
		ActorSubject: ev.Subject,
		ActorType:    string(auth.PrincipalUser),
	}

	// 1. Resolve Principal if stored in Context
	if p, ok := auth.PrincipalFrom(ctx); ok && p.Subject != "" {
		record.ActorSubject = p.Subject
		record.ActorType = string(p.Type)
	}

	// 2. Resolve organization context
	if s.cfg.OrgResolver != nil {
		record.OrganizationID = s.cfg.OrgResolver(ctx, ev)
	}

	// 3. Inspect payload for specialized actor, target, organization, and networking data
	s.extractPayloadContext(record, ev)

	return record
}

func deriveOutcome(ev auth.Event) Outcome {
	name := strings.ToLower(string(ev.Name))
	if strings.Contains(name, "denied") ||
		strings.Contains(name, "rejected") ||
		strings.Contains(name, "failed") ||
		strings.Contains(name, "revoked") && strings.Contains(name, "token.rejected") {
		return OutcomeFailure
	}
	return OutcomeSuccess
}

func (s *service) extractPayloadContext(record *AuditRecord, ev auth.Event) {
	if ev.Payload == nil {
		return
	}

	// Marshal to generic map for flexible inspection
	data, err := json.Marshal(ev.Payload)
	if err != nil {
		return
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}

	// Extract Actor
	if str, ok := m["actor_id"].(string); ok && str != "" {
		record.ActorSubject = str
		record.ActorType = string(auth.PrincipalUser)
	} else if str, ok := m["inviter_user_id"].(string); ok && str != "" {
		record.ActorSubject = str
		record.ActorType = string(auth.PrincipalUser)
	} else if str, ok := m["owner_id"].(string); ok && str != "" {
		record.ActorSubject = str
	}

	if pType, ok := m["principal_type"].(string); ok && pType != "" {
		record.ActorType = pType
	}

	// Extract Target details
	if targetUser, ok := m["target_user_id"].(string); ok && targetUser != "" {
		record.TargetType = "user"
		record.TargetID = targetUser
	} else if orgID, ok := m["organization_id"].(string); ok && orgID != "" {
		if record.OrganizationID == "" {
			record.OrganizationID = orgID
		}
		if teamID, ok := m["team_id"].(string); ok && teamID != "" {
			record.TargetType = "team"
			record.TargetID = teamID
		} else if invID, ok := m["invitation_id"].(string); ok && invID != "" {
			record.TargetType = "invitation"
			record.TargetID = invID
		} else if memberUser, ok := m["user_id"].(string); ok && memberUser != "" {
			record.TargetType = "membership"
			record.TargetID = memberUser
		} else {
			record.TargetType = "organization"
			record.TargetID = orgID
		}
	} else if keyID, ok := m["id"].(string); ok && strings.HasPrefix(string(ev.Name), "apikeys.") {
		record.TargetType = "api_key"
		record.TargetID = keyID
	} else if userID, ok := m["user_id"].(string); ok && userID != "" {
		record.TargetType = "user"
		record.TargetID = userID
	}

	// Extract IP Address & User Agent
	if ip, ok := m["ip_address"].(string); ok && ip != "" {
		record.IPAddress = ip
	}
	if ua, ok := m["user_agent"].(string); ok && ua != "" {
		record.UserAgent = ua
	}

	// Extract Error Message
	if errMsg, ok := m["error"].(string); ok && errMsg != "" {
		record.ErrorMessage = errMsg
		record.Outcome = OutcomeFailure
	} else if reason, ok := m["reason"].(string); ok && reason != "" {
		if record.Outcome == OutcomeFailure {
			record.ErrorMessage = reason
		}
	}
}

func (s *service) workerLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()

	batch := make([]*AuditRecord, 0, s.cfg.BatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		toPersist := make([]*AuditRecord, len(batch))
		copy(toPersist, batch)
		batch = batch[:0]

		bgCtx := context.Background()
		if err := s.cfg.Store.RecordBatch(bgCtx, toPersist); err != nil {
			s.logger.Error("audit: async batch persist failed", "error", err, "count", len(toPersist))
		}
	}

	for {
		select {
		case record, ok := <-s.asyncCh:
			if !ok {
				flush()
				return
			}
			batch = append(batch, record)
			if len(batch) >= s.cfg.BatchSize {
				flush()
			}

		case <-ticker.C:
			flush()

		case <-s.stopCh:
			// Drain remaining records before exit
			for {
				select {
				case record, ok := <-s.asyncCh:
					if !ok {
						flush()
						return
					}
					batch = append(batch, record)
					if len(batch) >= s.cfg.BatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

// Close gracefully flushes pending asynchronous records and waits for workers.
func (s *service) Close() error {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		if s.asyncCh != nil {
			close(s.asyncCh)
		}
		s.wg.Wait()
	})
	return nil
}
