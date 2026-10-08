package phone

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Message encapsulates a dispatched verification SMS or voice message.
type Message struct {
	// To is the destination phone number formatted in E.164.
	To string

	// Body is the rendered text body delivered to the recipient.
	Body string

	// Code is the raw numeric verification code.
	Code string

	// Purpose is the semantic action (e.g. "authenticate", "verify", "change").
	Purpose string

	// TTL is the active validity lifespan of the verification code.
	TTL time.Duration

	// Metadata carries optional vendor-specific or application-level parameters.
	Metadata map[string]string
}

// MessageBuilder formats the SMS message body and parameters before transmission.
type MessageBuilder func(to, code, purpose string, ttl time.Duration) Message

// PhoneProvider defines the vendor-agnostic interface for delivering phone messages (SMS/voice).
// Implementations adapt services such as Twilio, Vonage, AWS SNS, Infobip, or internal gateways.
type PhoneProvider interface {
	Send(ctx context.Context, msg Message) error
}

// DefaultMessageBuilder returns the standard transactional SMS copy.
func DefaultMessageBuilder(to, code, purpose string, ttl time.Duration) Message {
	mins := int(ttl.Minutes())
	if mins <= 0 {
		mins = 1
	}

	var action string
	switch purpose {
	case PurposeAuthenticate:
		action = "sign in"
	case PurposeVerify:
		action = "verify your phone number"
	case PurposeChange:
		action = "change your phone number"
	default:
		action = "complete verification"
	}

	body := fmt.Sprintf("Your verification code to %s is: %s. Valid for %d minutes. Never share this code with anyone.", action, code, mins)

	return Message{
		To:      to,
		Body:    body,
		Code:    code,
		Purpose: purpose,
		TTL:     ttl,
	}
}

// MockProvider is an in-memory, thread-safe PhoneProvider for unit and integration testing.
type MockProvider struct {
	mu       sync.RWMutex
	sent     []Message
	errToRet error
}

var _ PhoneProvider = (*MockProvider)(nil)

// NewMockProvider creates an empty MockProvider.
func NewMockProvider() *MockProvider {
	return &MockProvider{
		sent: make([]Message, 0),
	}
}

// Send records the message in memory or returns the simulated error.
func (m *MockProvider) Send(ctx context.Context, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.errToRet != nil {
		return m.errToRet
	}
	m.sent = append(m.sent, msg)
	return nil
}

// Messages returns a copy of all recorded dispatched messages.
func (m *MockProvider) Messages() []Message {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Message, len(m.sent))
	copy(out, m.sent)
	return out
}

// LastMessage returns the most recently sent message, or nil if none.
func (m *MockProvider) LastMessage() *Message {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.sent) == 0 {
		return nil
	}
	last := m.sent[len(m.sent)-1]
	return &last
}

// SetError instructs the mock provider to return an error on subsequent Send calls.
func (m *MockProvider) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errToRet = err
}

// Reset clears recorded messages and resets errors.
func (m *MockProvider) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = m.sent[:0]
	m.errToRet = nil
}
