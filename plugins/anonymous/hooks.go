package anonymous

import (
	"net/http"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

type accountLinkInterceptor struct {
	http.ResponseWriter
	plugin       *Plugin
	req          *http.Request
	prevAnonUser *entity.User
	prevAnonSess *entity.Session
	wroteHeader  bool
}

func (w *accountLinkInterceptor) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	if code >= 200 && code < 300 && w.prevAnonUser != nil && w.prevAnonUser.IsAnonymous {
		var newUser *entity.User
		var newSess *entity.Session

		if w.plugin.ctx != nil {
			if u, ok := w.plugin.ctx.Get("auth:user"); ok {
				if userEntity, ok := u.(*entity.User); ok && userEntity != nil && !userEntity.IsAnonymous {
					newUser = userEntity
				}
			}
			if s, ok := w.plugin.ctx.Get("auth:session"); ok {
				if sessEntity, ok := s.(*entity.Session); ok && sessEntity != nil {
					newSess = sessEntity
				}
			}
		}

		if newUser != nil {
			linkData := &OnLinkAccountData{
				AnonymousUser: UserSessionPair{
					User:    w.prevAnonUser,
					Session: w.prevAnonSess,
				},
				NewUser: UserSessionPair{
					User:    newUser,
					Session: newSess,
				},
			}
			_ = w.plugin.LinkAccount(w.req.Context(), linkData)
		}
	}

	w.ResponseWriter.WriteHeader(code)
}

func (w *accountLinkInterceptor) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// PostAuthAccountLinkHook creates a net/http middleware that automatically detects when a guest user
// transitions to an authenticated permanent user, triggering OnLinkAccount and account cleanup.
func (p *Plugin) PostAuthAccountLinkHook(prevUser *entity.User, prevSess *entity.Session) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			interceptor := &accountLinkInterceptor{
				ResponseWriter: w,
				plugin:         p,
				req:            r,
				prevAnonUser:   prevUser,
				prevAnonSess:   prevSess,
			}

			next.ServeHTTP(interceptor, r)

			if !interceptor.wroteHeader {
				interceptor.WriteHeader(http.StatusOK)
			}
		})
	}
}
