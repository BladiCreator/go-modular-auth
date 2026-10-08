package sdk

import "context"

// Event represents a system event dispatched to subscribers.
type Event struct {
	Name    string
	Payload any
}

// EventHandler is a callback invoked when an event is emitted.
type EventHandler func(ctx context.Context, e Event)

// EventSubscriber allows modules to subscribe to events.
type EventSubscriber interface {
	Subscribe(eventName string, handler EventHandler)
}
