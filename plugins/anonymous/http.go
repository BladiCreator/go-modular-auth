package anonymous

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// SetAnonymousSessionCookie sets the session token cookie on the HTTP response writer.
func SetAnonymousSessionCookie(w http.ResponseWriter, token string, cfg Config) {
	if w == nil || token == "" {
		return
	}

	cookie := &http.Cookie{
		Name:     cfg.CookieName,
		Value:    token,
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		Expires:  time.Now().Add(cfg.CookieMaxAge),
		MaxAge:   int(cfg.CookieMaxAge.Seconds()),
		Secure:   cfg.CookieSecure,
		HttpOnly: true,
		SameSite: cfg.CookieSameSite,
	}

	http.SetCookie(w, cookie)
}

// ClearAnonymousSessionCookie expires and deletes the session token cookie.
func ClearAnonymousSessionCookie(w http.ResponseWriter, cfg Config) {
	if w == nil {
		return
	}

	cookie := &http.Cookie{
		Name:     cfg.CookieName,
		Value:    "",
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   cfg.CookieSecure,
		HttpOnly: true,
		SameSite: cfg.CookieSameSite,
	}

	http.SetCookie(w, cookie)
}

// ServeSignInAnonymous handles HTTP POST /sign-in/anonymous requests.
func (p *Plugin) ServeSignInAnonymous(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params SignInAnonymousParams
	_ = json.NewDecoder(r.Body).Decode(&params)

	if params.IPAddress == "" {
		params.IPAddress = r.RemoteAddr
	}
	if params.UserAgent == "" {
		params.UserAgent = r.UserAgent()
	}

	var currentSession *entity.Session
	if p.ctx != nil {
		if s, ok := p.ctx.Get("auth:session"); ok {
			if sessEntity, ok := s.(*entity.Session); ok {
				currentSession = sessEntity
			}
		}
	}

	res, err := p.SignInAnonymous(r.Context(), currentSession, params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": err.Error(),
		})
		return
	}

	SetAnonymousSessionCookie(w, res.Token, p.config)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

// ServeDeleteAnonymousUser handles HTTP POST /delete-anonymous-user requests.
func (p *Plugin) ServeDeleteAnonymousUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var activeSession *entity.Session
	if p.ctx != nil {
		if s, ok := p.ctx.Get("auth:session"); ok {
			if sessEntity, ok := s.(*entity.Session); ok {
				activeSession = sessEntity
			}
		}
	}

	res, err := p.DeleteAnonymousUser(r.Context(), activeSession)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		status := http.StatusBadRequest
		if err == ErrUserIsNotAnonymous {
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": err.Error(),
		})
		return
	}

	ClearAnonymousSessionCookie(w, p.config)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}
