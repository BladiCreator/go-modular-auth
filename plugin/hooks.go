package plugin

import (
	"context"
	"log/slog"
	"reflect"
	"slices"
	"sync"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Typed signatures for core lifecycle callbacks.
type (
	UserSignedUpHookFn         = func(ctx context.Context, user *entity.User)
	UserSignedInHookFn         = func(ctx context.Context, data *dto.SessionData)
	SessionCreatedHookFn       = func(ctx context.Context, session *entity.Session)
	SessionRevokedHookFn       = func(ctx context.Context, token string, session *entity.Session)
	SessionValidatedHookFn     = func(ctx context.Context, data *dto.SessionData)
	PasswordResetReqHookFn     = func(ctx context.Context, email string, token *entity.Verification)
	PasswordResetCompHookFn    = func(ctx context.Context, userID string)
	EmailVerificationReqHookFn = func(ctx context.Context, email string, token *entity.Verification)
	EmailVerifiedHookFn        = func(ctx context.Context, user *entity.User)
	PasswordChangedHookFn      = func(ctx context.Context, user *entity.User)
)

// Hooks provides strongly typed lifecycle hooks and a native pub/sub event dispatcher
// with zero external dependencies, complete type safety, and context awareness.
type Hooks struct {
	mu    sync.RWMutex
	async bool

	// Strongly-typed lifecycle callbacks
	userSignedUpCallbacks         []UserSignedUpHookFn
	userSignedInCallbacks         []UserSignedInHookFn
	sessionCreatedCallbacks       []SessionCreatedHookFn
	sessionRevokedCallbacks       []SessionRevokedHookFn
	sessionValidatedCallbacks     []SessionValidatedHookFn
	passwordResetReqCallbacks     []PasswordResetReqHookFn
	passwordResetCompCallbacks    []PasswordResetCompHookFn
	emailVerificationReqCallbacks []EmailVerificationReqHookFn
	emailVerifiedCallbacks        []EmailVerifiedHookFn
	passwordChangedCallbacks      []PasswordChangedHookFn

	// Topic-based subscribers for plugin-specific events
	subscribers map[string][]any
}

// NewHooks initializes an empty native Hooks instance.
func NewHooks(async ...bool) *Hooks {
	isAsync := false
	if len(async) > 0 {
		isAsync = async[0]
	}
	return &Hooks{
		async:       isAsync,
		subscribers: make(map[string][]any),
	}
}

// SetAsync configures whether lifecycle hooks and events run asynchronously.
func (h *Hooks) SetAsync(async bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.async = async
}

// --- Strongly-Typed Lifecycle Hook Registrations ---

// OnUserSignedUp registers a callback invoked after a new user registers successfully.
func (h *Hooks) OnUserSignedUp(fn func(ctx context.Context, user *entity.User)) *Hooks {
	if fn == nil {
		return h
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.userSignedUpCallbacks = append(h.userSignedUpCallbacks, fn)
	return h
}

// OnUserSignedIn registers a callback invoked after a user successfully signs in and session is issued.
func (h *Hooks) OnUserSignedIn(fn func(ctx context.Context, data *dto.SessionData)) *Hooks {
	if fn == nil {
		return h
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.userSignedInCallbacks = append(h.userSignedInCallbacks, fn)
	return h
}

// OnSessionCreated registers a callback invoked whenever an active user session is persisted.
func (h *Hooks) OnSessionCreated(fn func(ctx context.Context, session *entity.Session)) *Hooks {
	if fn == nil {
		return h
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessionCreatedCallbacks = append(h.sessionCreatedCallbacks, fn)
	return h
}

// OnSessionRevoked registers a callback invoked whenever an active session is revoked.
func (h *Hooks) OnSessionRevoked(fn func(ctx context.Context, token string, session *entity.Session)) *Hooks {
	if fn == nil {
		return h
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessionRevokedCallbacks = append(h.sessionRevokedCallbacks, fn)
	return h
}

// OnSessionValidated registers a callback invoked whenever an active session is successfully validated.
func (h *Hooks) OnSessionValidated(fn func(ctx context.Context, data *dto.SessionData)) *Hooks {
	if fn == nil {
		return h
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessionValidatedCallbacks = append(h.sessionValidatedCallbacks, fn)
	return h
}

// OnPasswordResetRequested registers a callback invoked when a password reset token is generated.
func (h *Hooks) OnPasswordResetRequested(fn func(ctx context.Context, email string, token *entity.Verification)) *Hooks {
	if fn == nil {
		return h
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.passwordResetReqCallbacks = append(h.passwordResetReqCallbacks, fn)
	return h
}

// OnPasswordResetCompleted registers a callback invoked after a password has been reset.
func (h *Hooks) OnPasswordResetCompleted(fn func(ctx context.Context, userID string)) *Hooks {
	if fn == nil {
		return h
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.passwordResetCompCallbacks = append(h.passwordResetCompCallbacks, fn)
	return h
}

// OnEmailVerificationRequested registers a callback invoked when an email verification token is generated.
func (h *Hooks) OnEmailVerificationRequested(fn func(ctx context.Context, email string, token *entity.Verification)) *Hooks {
	if fn == nil {
		return h
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.emailVerificationReqCallbacks = append(h.emailVerificationReqCallbacks, fn)
	return h
}

// OnEmailVerified registers a callback invoked after an email address has been verified.
func (h *Hooks) OnEmailVerified(fn func(ctx context.Context, user *entity.User)) *Hooks {
	if fn == nil {
		return h
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.emailVerifiedCallbacks = append(h.emailVerifiedCallbacks, fn)
	return h
}

// OnPasswordChanged registers a callback invoked after a user password has been updated.
func (h *Hooks) OnPasswordChanged(fn func(ctx context.Context, user *entity.User)) *Hooks {
	if fn == nil {
		return h
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.passwordChangedCallbacks = append(h.passwordChangedCallbacks, fn)
	return h
}

// --- Strongly-Typed Lifecycle Hook Dispatchers ---

// DispatchUserSignedUp dispatches user sign-up notifications to all registered listeners.
func (h *Hooks) DispatchUserSignedUp(ctx context.Context, user *entity.User) {
	if h == nil || user == nil {
		return
	}
	h.mu.RLock()
	callbacks := slices.Clone(h.userSignedUpCallbacks)
	isAsync := h.async
	h.mu.RUnlock()

	exec := func() {
		for _, cb := range callbacks {
			safeInvoke(func() { cb(ctx, user) })
		}
		// Also dispatch to generic topic for plugins listening on legacy topic
		h.Dispatch(ctx, "emailpassword:signup:after", user)
	}

	if isAsync {
		go exec()
	} else {
		exec()
	}
}

// DispatchUserSignedIn dispatches user sign-in notifications to all registered listeners.
func (h *Hooks) DispatchUserSignedIn(ctx context.Context, data *dto.SessionData) {
	if h == nil || data == nil {
		return
	}
	h.mu.RLock()
	callbacks := slices.Clone(h.userSignedInCallbacks)
	isAsync := h.async
	h.mu.RUnlock()

	exec := func() {
		for _, cb := range callbacks {
			safeInvoke(func() { cb(ctx, data) })
		}
		h.Dispatch(ctx, "emailpassword:signin:after", data)
	}

	if isAsync {
		go exec()
	} else {
		exec()
	}
}

// DispatchSessionCreated dispatches session creation notifications to all registered listeners.
func (h *Hooks) DispatchSessionCreated(ctx context.Context, session *entity.Session) {
	if h == nil || session == nil {
		return
	}
	h.mu.RLock()
	callbacks := slices.Clone(h.sessionCreatedCallbacks)
	isAsync := h.async
	h.mu.RUnlock()

	exec := func() {
		for _, cb := range callbacks {
			safeInvoke(func() { cb(ctx, session) })
		}
		h.Dispatch(ctx, "auth:session:created", session)
	}

	if isAsync {
		go exec()
	} else {
		exec()
	}
}

// DispatchSessionRevoked dispatches session revocation notifications.
func (h *Hooks) DispatchSessionRevoked(ctx context.Context, token string, session *entity.Session) {
	if h == nil {
		return
	}
	h.mu.RLock()
	callbacks := slices.Clone(h.sessionRevokedCallbacks)
	isAsync := h.async
	h.mu.RUnlock()

	exec := func() {
		for _, cb := range callbacks {
			safeInvoke(func() { cb(ctx, token, session) })
		}
		h.Dispatch(ctx, "auth:session:revoked", token)
	}

	if isAsync {
		go exec()
	} else {
		exec()
	}
}

// DispatchSessionValidated dispatches session validation notifications.
func (h *Hooks) DispatchSessionValidated(ctx context.Context, data *dto.SessionData) {
	if h == nil || data == nil {
		return
	}
	h.mu.RLock()
	callbacks := slices.Clone(h.sessionValidatedCallbacks)
	isAsync := h.async
	h.mu.RUnlock()

	exec := func() {
		for _, cb := range callbacks {
			safeInvoke(func() { cb(ctx, data) })
		}
		h.Dispatch(ctx, "auth:session:validated", data)
	}

	if isAsync {
		go exec()
	} else {
		exec()
	}
}

// DispatchPasswordResetRequested dispatches password reset request notifications.
func (h *Hooks) DispatchPasswordResetRequested(ctx context.Context, email string, token *entity.Verification) {
	if h == nil {
		return
	}
	h.mu.RLock()
	callbacks := slices.Clone(h.passwordResetReqCallbacks)
	isAsync := h.async
	h.mu.RUnlock()

	exec := func() {
		for _, cb := range callbacks {
			safeInvoke(func() { cb(ctx, email, token) })
		}
		h.Dispatch(ctx, "emailpassword:password_reset:requested", token)
	}

	if isAsync {
		go exec()
	} else {
		exec()
	}
}

// DispatchPasswordResetCompleted dispatches password reset completed notifications.
func (h *Hooks) DispatchPasswordResetCompleted(ctx context.Context, userID string) {
	if h == nil {
		return
	}
	h.mu.RLock()
	callbacks := slices.Clone(h.passwordResetCompCallbacks)
	isAsync := h.async
	h.mu.RUnlock()

	exec := func() {
		for _, cb := range callbacks {
			safeInvoke(func() { cb(ctx, userID) })
		}
		h.Dispatch(ctx, "emailpassword:password_reset:completed", userID)
	}

	if isAsync {
		go exec()
	} else {
		exec()
	}
}

// DispatchEmailVerificationRequested dispatches email verification request notifications.
func (h *Hooks) DispatchEmailVerificationRequested(ctx context.Context, email string, token *entity.Verification) {
	if h == nil {
		return
	}
	h.mu.RLock()
	callbacks := slices.Clone(h.emailVerificationReqCallbacks)
	isAsync := h.async
	h.mu.RUnlock()

	exec := func() {
		for _, cb := range callbacks {
			safeInvoke(func() { cb(ctx, email, token) })
		}
		h.Dispatch(ctx, "emailpassword:email_verification:requested", token)
	}

	if isAsync {
		go exec()
	} else {
		exec()
	}
}

// DispatchEmailVerified dispatches email verified notifications.
func (h *Hooks) DispatchEmailVerified(ctx context.Context, user *entity.User) {
	if h == nil || user == nil {
		return
	}
	h.mu.RLock()
	callbacks := slices.Clone(h.emailVerifiedCallbacks)
	isAsync := h.async
	h.mu.RUnlock()

	exec := func() {
		for _, cb := range callbacks {
			safeInvoke(func() { cb(ctx, user) })
		}
		h.Dispatch(ctx, "emailpassword:email_verification:verified", user)
	}

	if isAsync {
		go exec()
	} else {
		exec()
	}
}

// DispatchPasswordChanged dispatches password changed notifications.
func (h *Hooks) DispatchPasswordChanged(ctx context.Context, user *entity.User) {
	if h == nil || user == nil {
		return
	}
	h.mu.RLock()
	callbacks := slices.Clone(h.passwordChangedCallbacks)
	isAsync := h.async
	h.mu.RUnlock()

	exec := func() {
		for _, cb := range callbacks {
			safeInvoke(func() { cb(ctx, user) })
		}
		h.Dispatch(ctx, "emailpassword:password_change:after", user)
	}

	if isAsync {
		go exec()
	} else {
		exec()
	}
}

// --- Topic-Based Native Pub/Sub Dispatcher ---

// Subscribe registers a listener function for a specific topic string.
// Supported handler signatures:
//   - func(ctx context.Context, payload any)
//   - func(payload any)
//   - func(ctx context.Context, payload SpecificType)
//   - func(payload SpecificType)
func (h *Hooks) Subscribe(topic string, handler any) *Hooks {
	if h == nil || handler == nil || topic == "" {
		return h
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subscribers[topic] = append(h.subscribers[topic], handler)
	return h
}

// Dispatch invokes all registered subscribers for the given topic with the provided payload.
func (h *Hooks) Dispatch(ctx context.Context, topic string, payload any) {
	if h == nil || topic == "" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	h.mu.RLock()
	subs, ok := h.subscribers[topic]
	if !ok || len(subs) == 0 {
		h.mu.RUnlock()
		return
	}
	copied := slices.Clone(subs)
	isAsync := h.async
	h.mu.RUnlock()

	exec := func() {
		for _, sub := range copied {
			invokeSubscriber(sub, ctx, payload)
		}
	}

	if isAsync {
		go exec()
	} else {
		exec()
	}
}

// DispatchAsync explicitly invokes topic subscribers in a background goroutine.
func (h *Hooks) DispatchAsync(ctx context.Context, topic string, payload any) {
	if h == nil || topic == "" {
		return
	}
	go h.Dispatch(ctx, topic, payload)
}

// Publish is a convenience wrapper enabling drop-in compatibility for plugins and tests.
// It accepts either (topic, payload) or (topic, ctx, payload).
func (h *Hooks) Publish(topic string, args ...any) {
	if h == nil || topic == "" || len(args) == 0 {
		return
	}

	ctx := context.Background()
	var payload any

	if len(args) == 1 {
		payload = args[0]
	} else if len(args) >= 2 {
		if c, ok := args[0].(context.Context); ok {
			ctx = c
			payload = args[1]
		} else {
			payload = args[0]
		}
	}

	h.Dispatch(ctx, topic, payload)
}

// invokeSubscriber safely calls an arbitrary subscriber function with the given context and payload.
func invokeSubscriber(sub any, ctx context.Context, payload any) {
	defer func() {
		_ = recover() // Never allow a subscriber panic to crash the authentication engine
	}()

	switch fn := sub.(type) {
	case func(context.Context, any):
		fn(ctx, payload)
		return
	case func(any):
		fn(payload)
		return
	}

	// Reflection fallback for typed handler signatures e.g. func(ctx context.Context, p *SignUpEventPayload)
	fnVal := reflect.ValueOf(sub)
	if fnVal.Kind() != reflect.Func {
		return
	}
	fnType := fnVal.Type()
	numArgs := fnType.NumIn()

	switch numArgs {
	case 1:
		argType := fnType.In(0)
		argVal := reflect.ValueOf(payload)
		if !argVal.IsValid() {
			argVal = reflect.Zero(argType)
		} else if !argVal.Type().AssignableTo(argType) && argVal.Type().ConvertibleTo(argType) {
			argVal = argVal.Convert(argType)
		}
		if argVal.Type().AssignableTo(argType) {
			fnVal.Call([]reflect.Value{argVal})
		}
	case 2:
		arg0Val := reflect.ValueOf(ctx)
		arg1Type := fnType.In(1)
		arg1Val := reflect.ValueOf(payload)
		if !arg1Val.IsValid() {
			arg1Val = reflect.Zero(arg1Type)
		} else if !arg1Val.Type().AssignableTo(arg1Type) && arg1Val.Type().ConvertibleTo(arg1Type) {
			arg1Val = arg1Val.Convert(arg1Type)
		}
		if arg0Val.Type().AssignableTo(fnType.In(0)) && arg1Val.Type().AssignableTo(arg1Type) {
			fnVal.Call([]reflect.Value{arg0Val, arg1Val})
		}
	}
}

func safeInvoke(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Default().Error("Hooks: recovered panic in lifecycle hook", "panic", r)
		}
	}()
	fn()
}
