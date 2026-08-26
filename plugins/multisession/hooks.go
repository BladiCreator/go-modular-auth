package multisession

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// AfterSessionCreated runs after a new session is created to enforce session limits and emit multi-session cookies.
func (p *Plugin) AfterSessionCreated(ctx context.Context, w http.ResponseWriter, r *http.Request, newSession *entity.Session) error {
	if newSession == nil || newSession.Token == "" {
		return nil
	}

	existingTokens := p.ExtractMultiSessionTokens(r)
	tokensToDelete := make([]string, 0)
	activeDeviceCount := 0
	now := time.Now()

	for _, token := range existingTokens {
		sess, err := p.repo.GetSessionByToken(ctx, token)
		if err != nil || sess == nil || sess.ExpiresAt.Before(now) {
			tokensToDelete = append(tokensToDelete, token)
			p.ExpireCookie(w, p.GetMultiCookieName(token))
			continue
		}

		if sess.UserID == newSession.UserID {
			tokensToDelete = append(tokensToDelete, token)
			p.ExpireCookie(w, p.GetMultiCookieName(token))
		} else {
			activeDeviceCount++
		}
	}

	if len(tokensToDelete) > 0 {
		_ = p.repo.DeleteSessions(ctx, tokensToDelete)
	}

	if p.config.MaximumSessions <= 0 || activeDeviceCount < p.config.MaximumSessions {
		p.SetMultiSessionCookie(w, newSession.Token, newSession.ExpiresAt)
	}

	p.publishEvent(EventSessionCreated, ctx, &SessionCreatedEventPayload{
		Session: newSession,
	})

	return nil
}

// AfterSignOut runs during sign-out to perform mass revocation of all multi-sessions registered on the device.
func (p *Plugin) AfterSignOut(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	multiPrefix := p.config.CookiePrefix + "_multi-"
	verifiedTokens := make([]string, 0)

	if r != nil {
		for _, c := range r.Cookies() {
			if strings.HasPrefix(c.Name, multiPrefix) {
				rawToken, err := VerifyCookieValue(c.Value, p.config.Secret)
				if err == nil && rawToken != "" {
					verifiedTokens = append(verifiedTokens, rawToken)
				}
				p.ExpireCookie(w, c.Name)
			}
		}
	}

	if len(verifiedTokens) > 0 {
		_ = p.repo.DeleteSessions(ctx, verifiedTokens)
	}

	p.ExpireMainSessionCookie(w)

	p.publishEvent(EventSignOut, ctx, &SignOutEventPayload{
		RevokedTokens: verifiedTokens,
	})

	return nil
}

