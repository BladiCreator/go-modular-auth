package customsession_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/asaskevich/EventBus"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/customsession"
)

func TestCustomSession_BasicTransformation(t *testing.T) {
	transformFn := func(ctx context.Context, sData *dto.SessionData, req *http.Request) (any, error) {
		type EnrichedResponse struct {
			User        *entity.User `json:"user"`
			Session     *entity.Session `json:"session"`
			Permissions []string     `json:"permissions"`
		}
		return EnrichedResponse{
			User:        sData.User,
			Session:     sData.Session,
			Permissions: []string{"read:users", "write:users"},
		}, nil
	}

	p := customsession.New(nil, customsession.WithTransformFunc(transformFn))
	if p.ID() != "custom-session" {
		t.Fatalf("expected plugin ID 'custom-session', got '%s'", p.ID())
	}

	initialSession := &dto.SessionData{
		User: &entity.User{
			ID:    "usr-123",
			Email: "admin@example.com",
			Role:  "admin",
		},
		Session: &entity.Session{
			ID:     "sess-456",
			UserID: "usr-123",
		},
	}

	req := httptest.NewRequest("GET", "/get-session", nil)
	result, err := p.TransformSession(context.Background(), initialSession, req)
	if err != nil {
		t.Fatalf("unexpected error during TransformSession: %v", err)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal transform result: %v", err)
	}

	if !bytes.Contains(encoded, []byte("read:users")) {
		t.Errorf("expected transformed response to contain permissions, got: %s", string(encoded))
	}
}

func TestCustomSession_MemoryRepository(t *testing.T) {
	repo := customsession.NewMemoryRepository()
	ctx := context.Background()

	err := repo.SaveCustomUserFields(ctx, "usr-99", map[string]any{
		"org_id": "org-super",
		"tier":   "enterprise",
	})
	if err != nil {
		t.Fatalf("failed to save user fields: %v", err)
	}

	fields, err := repo.GetCustomUserFields(ctx, "usr-99")
	if err != nil {
		t.Fatalf("failed to get user fields: %v", err)
	}
	if fields["org_id"] != "org-super" || fields["tier"] != "enterprise" {
		t.Errorf("unexpected user fields returned: %v", fields)
	}
}

func TestCustomSession_EventBusEmission(t *testing.T) {
	bus := EventBus.New()
	ctx := plugin.NewContext(nil, bus)

	beforeFired := false
	afterFired := false

	_ = bus.SubscribeAsync(customsession.EventTransformBefore, func(payload *customsession.TransformEventPayload) {
		beforeFired = true
	}, false)

	_ = bus.SubscribeAsync(customsession.EventTransformAfter, func(payload *customsession.TransformEventPayload) {
		afterFired = true
	}, false)

	p := customsession.New(nil)
	if err := p.Init(ctx); err != nil {
		t.Fatalf("failed to init plugin: %v", err)
	}

	sData := &dto.SessionData{
		User: &entity.User{ID: "u1"},
	}
	_, err := p.TransformSession(context.Background(), sData, nil)
	if err != nil {
		t.Fatalf("unexpected transform error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if !beforeFired {
		t.Errorf("expected EventTransformBefore to be emitted")
	}
	if !afterFired {
		t.Errorf("expected EventTransformAfter to be emitted")
	}
}

func TestCustomSession_SessionInterceptor(t *testing.T) {
	transformFn := func(ctx context.Context, sData *dto.SessionData, req *http.Request) (any, error) {
		sData.Set("custom_role", "superuser")
		return sData, nil
	}

	p := customsession.New(nil, customsession.WithTransformFunc(transformFn))

	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "token123", Path: "/"})
		w.Header().Set("X-Custom-Header", "preserved")
		sData := dto.SessionData{
			User:    &entity.User{ID: "usr-1", Email: "test@example.com"},
			Session: &entity.Session{ID: "sess-1", UserID: "usr-1"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(sData)
	})

	handler := p.SessionInterceptor(targetHandler)

	req := httptest.NewRequest("GET", "/api/auth/get-session", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if rec.Header().Get("X-Custom-Header") != "preserved" {
		t.Errorf("expected X-Custom-Header to be preserved, got '%s'", rec.Header().Get("X-Custom-Header"))
	}

	cookies := rec.Result().Cookies()
	foundCookie := false
	for _, c := range cookies {
		if c.Name == "session_id" && c.Value == "token123" {
			foundCookie = true
			break
		}
	}
	if !foundCookie {
		t.Errorf("expected Set-Cookie to be preserved in HTTP response")
	}

	if !bytes.Contains(rec.Body.Bytes(), []byte("superuser")) {
		t.Errorf("expected body to contain transformed extra field 'superuser', got: %s", rec.Body.String())
	}
}

func TestCustomSession_MutateListDeviceSessions(t *testing.T) {
	transformFn := func(ctx context.Context, sData *dto.SessionData, req *http.Request) (any, error) {
		sData.Set("device_status", "active")
		return sData, nil
	}

	p := customsession.New(nil,
		customsession.WithTransformFunc(transformFn),
		customsession.WithMutateListDeviceSessions(true),
	)

	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions := []dto.SessionData{
			{User: &entity.User{ID: "u1"}, Session: &entity.Session{ID: "s1"}},
			{User: &entity.User{ID: "u1"}, Session: &entity.Session{ID: "s2"}},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(sessions)
	})

	handler := p.SessionInterceptor(targetHandler)

	req := httptest.NewRequest("GET", "/api/auth/multi-session/list-device-sessions", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if !bytes.Contains(rec.Body.Bytes(), []byte("device_status")) {
		t.Errorf("expected device list body to contain transformed fields, got: %s", rec.Body.String())
	}
}

func TestCustomSession_FilterUnregisteredFields(t *testing.T) {
	p := customsession.New(nil,
		customsession.WithUserAdditionalFields(customsession.AdditionalFieldDefinition{
			Name: "allowed_field",
			Type: customsession.FieldTypeString,
		}),
		customsession.WithFilterUnregisteredFields(true),
	)

	sData := &dto.SessionData{
		User: &entity.User{ID: "u1"},
	}
	sData.Set("allowed_field", "valid")
	sData.Set("secret_internal_field", "should_be_removed")

	sanitized := p.SanitizePayload(sData).(*dto.SessionData)
	if sanitized.Extra["allowed_field"] != "valid" {
		t.Errorf("expected allowed_field to be retained")
	}
	if _, exists := sanitized.Extra["secret_internal_field"]; exists {
		t.Errorf("expected secret_internal_field to be filtered out")
	}
}

func TestCustomSession_TransformErrorHandling(t *testing.T) {
	errTransform := errors.New("database resolution error")
	p := customsession.New(nil, customsession.WithTransformFunc(func(ctx context.Context, sData *dto.SessionData, req *http.Request) (any, error) {
		return nil, errTransform
	}))

	sData := &dto.SessionData{User: &entity.User{ID: "u1"}}
	_, err := p.TransformSession(context.Background(), sData, nil)
	if err == nil {
		t.Fatalf("expected error during TransformSession, got nil")
	}
}
