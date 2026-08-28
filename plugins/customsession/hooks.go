package customsession

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
)

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

// SessionInterceptor creates an HTTP middleware that intercepts responses on GET /get-session and applies dynamic session transformation.
func (p *Plugin) SessionInterceptor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		isGetSession := strings.HasSuffix(path, "/get-session")
		isMultiSession := strings.HasSuffix(path, "/multi-session/list-device-sessions")

		if !isGetSession && (!isMultiSession || !p.config.MutateListDeviceSessions) {
			next.ServeHTTP(w, r)
			return
		}

		rec := newResponseRecorder(w)
		next.ServeHTTP(rec, r)

		// Preserve set headers and cookies set by downstream handlers
		for k, vv := range rec.Header() {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		if rec.statusCode != http.StatusOK {
			w.WriteHeader(rec.statusCode)
			_, _ = w.Write(rec.body.Bytes())
			return
		}

		if isGetSession {
			var sData dto.SessionData
			if err := json.Unmarshal(rec.body.Bytes(), &sData); err == nil && (sData.User != nil || sData.Session != nil) {
				transformed, err := p.TransformSession(r.Context(), &sData, r)
				if err == nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(transformed)
					return
				}
			}
		} else if isMultiSession && p.config.MutateListDeviceSessions {
			var sessions []dto.SessionData
			if err := json.Unmarshal(rec.body.Bytes(), &sessions); err == nil && len(sessions) > 0 {
				transformedList := make([]any, 0, len(sessions))
				for i := range sessions {
					t, err := p.TransformSession(r.Context(), &sessions[i], r)
					if err == nil {
						transformedList = append(transformedList, t)
					} else {
						transformedList = append(transformedList, &sessions[i])
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(transformedList)
				return
			}
		}

		// Fallback if unmarshaling/transform failed
		w.WriteHeader(rec.statusCode)
		_, _ = w.Write(rec.body.Bytes())
	})
}
