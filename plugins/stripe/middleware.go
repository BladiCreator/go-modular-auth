package stripe

import (
	"context"
	"net/http"
	"strings"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

type contextKey string

const (
	ReferenceIDContextKey contextKey = "stripe:reference_id"
	SubscriptionContextKey contextKey = "stripe:subscription"
)

// RequireActiveSubscription returns a net/http middleware that enforces that the requesting
// entity (user or organization referenceId) possesses an active or trialing subscription.
// Optional allowedPlans filter restricts access strictly to specified plan IDs.
func (p *Plugin) RequireActiveSubscription(allowedPlans ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			refID := p.resolveReferenceIDFromRequest(r)
			if refID == "" {
				http.Error(w, `{"error":"unauthorized","message":"missing referenceId or session context"}`, http.StatusUnauthorized)
				return
			}

			subs, err := p.repo.ListSubscriptionsByReferenceID(r.Context(), refID)
			if err != nil || len(subs) == 0 {
				http.Error(w, `{"error":"payment_required","message":"active subscription required"}`, http.StatusPaymentRequired)
				return
			}

			var activeSub *Subscription
			for _, sub := range subs {
				if IsActiveOrTrialing(sub) {
					activeSub = sub
					break
				}
			}

			if activeSub == nil {
				http.Error(w, `{"error":"payment_required","message":"subscription is not active"}`, http.StatusPaymentRequired)
				return
			}

			if len(allowedPlans) > 0 {
				planMatched := false
				for _, allowed := range allowedPlans {
					if strings.EqualFold(activeSub.Plan, allowed) {
						planMatched = true
						break
					}
				}
				if !planMatched {
					http.Error(w, `{"error":"forbidden","message":"plan upgrade required for this resource"}`, http.StatusForbidden)
					return
				}
			}

			ctx := context.WithValue(r.Context(), SubscriptionContextKey, activeSub)
			ctx = context.WithValue(ctx, ReferenceIDContextKey, refID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AuthorizeReference returns a net/http middleware that executes the configured AuthorizeReference
// callback to verify if the session user is permitted to perform the given action on a referenceId.
func (p *Plugin) AuthorizeReference(action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			refID := p.resolveReferenceIDFromRequest(r)
			if refID == "" {
				http.Error(w, `{"error":"unauthorized","message":"missing referenceId"}`, http.StatusUnauthorized)
				return
			}

			userID := p.resolveUserIDFromRequest(r)

			if p.config.Subscription != nil && p.config.Subscription.AuthorizeReference != nil {
				allowed, err := p.config.Subscription.AuthorizeReference(r.Context(), AuthorizeReferenceData{
					ReferenceID: refID,
					UserID:      userID,
					Action:      action,
				})
				if err != nil || !allowed {
					http.Error(w, `{"error":"forbidden","message":"unauthorized reference action"}`, http.StatusForbidden)
					return
				}
			}

			ctx := context.WithValue(r.Context(), ReferenceIDContextKey, refID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolveReferenceIDFromRequest extracts referenceId from context, query parameters, or active user session.
func (p *Plugin) resolveReferenceIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if refID, ok := r.Context().Value(ReferenceIDContextKey).(string); ok && refID != "" {
		return refID
	}
	if queryRef := r.URL.Query().Get("referenceId"); queryRef != "" {
		return queryRef
	}
	if headerRef := r.Header.Get("X-Reference-ID"); headerRef != "" {
		return headerRef
	}
	return p.resolveUserIDFromRequest(r)
}

// resolveUserIDFromRequest extracts authenticated User ID from plugin context if populated.
func (p *Plugin) resolveUserIDFromRequest(r *http.Request) string {
	if r == nil || p.ctx == nil {
		return ""
	}
	if u, ok := p.ctx.Get("auth:user"); ok {
		if userEntity, ok := u.(*entity.User); ok && userEntity != nil {
			return userEntity.ID
		}
	}
	return ""
}
