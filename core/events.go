package auth

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// EventName identifies an event. Plugins define their own names, prefixed
// with their module ID (e.g. "organizations.created").
type EventName string

// Core events.
const (
	EventUserCreated     EventName = "user.created"
	EventUserSignedIn    EventName = "user.signed_in"
	EventUserSignedOut   EventName = "user.signed_out"
	EventSessionCreated  EventName = "session.created"
	EventSessionRevoked  EventName = "session.revoked"
	EventPasswordChanged EventName = "password.changed"
	EventEmailVerified   EventName = "email.verified"
)

// Event notifies that something happened. Events are observational: they
// are published after the Store commit and cannot alter the workflow.
type Event struct {
	Name    EventName
	Time    time.Time
	Subject string // usually the user ID
	Payload any
}

// EventHandler handles an event. Handlers run synchronously, in
// subscription order; long work should be offloaded by the handler itself.
type EventHandler func(ctx context.Context, e Event)

// Events is the in-process event dispatcher.
type Events struct {
	mu       sync.RWMutex
	handlers map[EventName][]EventHandler
	all      []EventHandler
	logger   *slog.Logger
}

func newEvents(logger *slog.Logger) *Events {
	return &Events{handlers: map[EventName][]EventHandler{}, logger: logger}
}

// Subscribe registers h for the given event name.
func (e *Events) Subscribe(name EventName, h EventHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers[name] = append(e.handlers[name], h)
}

// SubscribeAll registers h for every event (useful for audit logging).
func (e *Events) SubscribeAll(h EventHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.all = append(e.all, h)
}

// Publish dispatches ev. A panicking handler is recovered and logged so an
// observer can never break an authentication workflow.
func (e *Events) Publish(ctx context.Context, ev Event) {
	e.mu.RLock()
	hs := append(append([]EventHandler(nil), e.handlers[ev.Name]...), e.all...)
	e.mu.RUnlock()
	for _, h := range hs {
		e.safeCall(ctx, h, ev)
	}
}

func (e *Events) safeCall(ctx context.Context, h EventHandler, ev Event) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.ErrorContext(ctx, "auth: event handler panicked", "event", ev.Name, "panic", r)
		}
	}()
	h(ctx, ev)
}
