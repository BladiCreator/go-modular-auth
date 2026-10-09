package sdk

import (
	auth "github.com/BladiCreator/go-modular-auth"
)

// Event is the event structure dispatched by the core engine.
type Event = auth.Event

// EventName represents the typed event identifier.
type EventName = auth.EventName

// EventHandler is the callback invoked when an event is published.
type EventHandler = auth.EventHandler

// Common core event names re-exported for plugin convenience.
const (
	EventUserCreated     = auth.EventUserCreated
	EventUserSignedIn    = auth.EventUserSignedIn
	EventUserSignedOut   = auth.EventUserSignedOut
	EventSessionCreated  = auth.EventSessionCreated
	EventSessionRevoked  = auth.EventSessionRevoked
	EventPasswordChanged = auth.EventPasswordChanged
	EventEmailVerified   = auth.EventEmailVerified
)
