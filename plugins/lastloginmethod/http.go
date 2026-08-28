package lastloginmethod

import (
	"net/http"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// SetLastLoginMethodCookie sets the last login method cookie on the HTTP response writer.
// Note: HttpOnly is explicitly set to false to allow client-side JavaScript access.
func SetLastLoginMethodCookie(w http.ResponseWriter, method string, cfg Config) {
	if w == nil || method == "" {
		return
	}

	cookie := &http.Cookie{
		Name:     cfg.CookieName,
		Value:    method,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Expires:  time.Now().Add(cfg.MaxAge),
		MaxAge:   int(cfg.MaxAge.Seconds()),
		Secure:   cfg.Secure,
		HttpOnly: false, // Explicitly false per user requirements and modular-auth spec
		SameSite: cfg.SameSite,
	}

	http.SetCookie(w, cookie)
}

// GetLastUsedLoginMethod extracts the last used login method from incoming HTTP request cookies.
func GetLastUsedLoginMethod(r *http.Request, cookieName string) string {
	if r == nil {
		return ""
	}
	if cookieName == "" {
		cookieName = DefaultCookieName
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie == nil {
		return ""
	}
	return cookie.Value
}

// ClearLastUsedLoginMethod expires and deletes the last login method cookie.
func ClearLastUsedLoginMethod(w http.ResponseWriter, cfg Config) {
	if w == nil {
		return
	}
	cookie := &http.Cookie{
		Name:     cfg.CookieName,
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   cfg.Secure,
		HttpOnly: false,
		SameSite: cfg.SameSite,
	}
	http.SetCookie(w, cookie)
}

type statusInterceptor struct {
	http.ResponseWriter
	plugin      *Plugin
	req         *http.Request
	wroteHeader bool
	statusCode  int
}

func (w *statusInterceptor) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = code

	if code >= 200 && code < 300 {
		method, ok := ResolveMethod(w.req.Context(), w.req, w.plugin.config)
		if ok && method != "" {
			userID := ""
			if w.plugin.ctx != nil {
				if u, ok := w.plugin.ctx.Get("auth:user"); ok {
					if userEntity, ok := u.(*entity.User); ok && userEntity != nil {
						userID = userEntity.ID
					}
				}
			}
			_, _ = w.plugin.ProcessLoginMethod(w.req.Context(), w.ResponseWriter, w.req, userID, method)
		}
	}

	w.ResponseWriter.WriteHeader(code)
}

func (w *statusInterceptor) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Middleware returns a net/http middleware handler to automatically intercept HTTP responses,
// resolve the login method based on configured route rules, and emit the cookie (and DB update if enabled)
// upon successful authentication responses (HTTP 2xx).
func (p *Plugin) Middleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			interceptor := &statusInterceptor{
				ResponseWriter: w,
				plugin:         p,
				req:            r,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(interceptor, r)

			// Fallback: If handler wrote no response body/header, trigger WriteHeader
			if !interceptor.wroteHeader {
				interceptor.WriteHeader(http.StatusOK)
			}
		})
	}
}
