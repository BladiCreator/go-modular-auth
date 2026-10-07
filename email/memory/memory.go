// Package memory provides a fake email.Sender that records messages in
// memory, for tests and local development.
package memory

import (
	"context"
	"sync"

	"github.com/BladiCreator/go-modular-auth/email"
)

// Sender records every sent message.
type Sender struct {
	mu       sync.Mutex
	messages []email.Message
}

var _ email.Sender = (*Sender)(nil)

// New returns an empty recording sender.
func New() *Sender { return &Sender{} }

// Send records the message.
func (s *Sender) Send(ctx context.Context, m email.Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.messages = append(s.messages, m)
	s.mu.Unlock()
	return nil
}

// Messages returns a copy of the recorded messages.
func (s *Sender) Messages() []email.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]email.Message(nil), s.messages...)
}

// Last returns the last recorded message.
func (s *Sender) Last() (email.Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.messages) == 0 {
		return email.Message{}, false
	}
	return s.messages[len(s.messages)-1], true
}
