package lastloginmethod

import (
	"context"
	"net/http"
)

// ProcessLoginMethod handles method resolution, GDPR consent evaluation, cookie issuance, and DB persistence.
func (p *Plugin) ProcessLoginMethod(ctx context.Context, w http.ResponseWriter, r *http.Request, userID string, overrideMethod string) (string, error) {
	method := overrideMethod
	if method == "" {
		resolved, ok := ResolveMethod(ctx, r, p.config)
		if !ok {
			return "", ErrMethodNotResolved
		}
		method = resolved
	}

	cookieStored := false
	if p.config.BeforeStoreCookie != nil {
		allowed, err := p.config.BeforeStoreCookie(ctx, r, method)
		if err == nil && allowed {
			SetLastLoginMethodCookie(w, method, p.config)
			cookieStored = true
		}
	} else {
		SetLastLoginMethodCookie(w, method, p.config)
		cookieStored = true
	}

	dbStored := false
	if p.config.StoreInDatabase && p.repo != nil && userID != "" {
		if err := p.repo.UpdateLastLoginMethod(ctx, userID, method); err == nil {
			dbStored = true
		}
	}

	p.publishEvent(EventLastLoginMethodSet, ctx, &LastLoginMethodEventPayload{
		UserID:       userID,
		Method:       method,
		CookieStored: cookieStored,
		DBStored:     dbStored,
	})

	return method, nil
}
