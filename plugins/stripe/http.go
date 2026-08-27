package stripe

import (
	"context"
	"io"
	"net/http"
)

// HandleWebhook is a net/http handler function that reads the raw HTTP request body,
// extracts the Stripe-Signature header, and delegates processing to ProcessWebhook.
func (p *Plugin) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"bad_request","message":"cannot read request body"}`, http.StatusBadRequest)
		return
	}

	signature := r.Header.Get("Stripe-Signature")
	if signature == "" {
		http.Error(w, `{"error":"bad_request","message":"missing Stripe-Signature header"}`, http.StatusBadRequest)
		return
	}

	if err := p.ProcessWebhook(r.Context(), payload, signature); err != nil {
		http.Error(w, `{"error":"webhook_failed","message":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"received":true}`))
}

// WebhookHandler returns a net/http Handler ready for mounting in any standard Go HTTP router or server.
func (p *Plugin) WebhookHandler() http.Handler {
	return http.HandlerFunc(p.HandleWebhook)
}

// SubscriptionFromContext retrieves the active Subscription injected into the request Context by middleware.
func SubscriptionFromContext(ctx context.Context) (*Subscription, bool) {
	if ctx == nil {
		return nil, false
	}
	sub, ok := ctx.Value(SubscriptionContextKey).(*Subscription)
	return sub, ok && sub != nil
}

// ReferenceIDFromContext retrieves the referenceId injected into the request Context by middleware.
func ReferenceIDFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	refID, ok := ctx.Value(ReferenceIDContextKey).(string)
	return refID, ok && refID != ""
}
