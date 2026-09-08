package httpauth

import (
	"net/http"
	"strings"
)

// TokenSource represents an extraction source for authentication tokens.
type TokenSource int

const (
	// SourceCookie extracts tokens from HTTP request cookies.
	SourceCookie TokenSource = iota + 1
	// SourceHeader extracts tokens from request HTTP headers (e.g., Authorization: Bearer).
	SourceHeader
	// SourceQuery extracts tokens from URL query parameters.
	SourceQuery
)

// Default extraction settings.
const (
	DefaultExtractCookieName   = "auth_session"
	DefaultExtractHeaderName   = "Authorization"
	DefaultExtractHeaderPrefix = "Bearer "
	DefaultExtractQueryParam   = "token"
)

// ExtractConfig holds configurable strategies for extracting tokens from an HTTP request.
type ExtractConfig struct {
	// Sources defines the ordered search cascade.
	Sources []TokenSource
	// CookieName specifies the session cookie name to look up.
	CookieName string
	// HeaderName specifies the HTTP header name.
	HeaderName string
	// HeaderPrefix specifies the prefix preceding the token in the header.
	HeaderPrefix string
	// QueryParam specifies the URL query parameter name.
	QueryParam string
}

// DefaultExtractConfig returns the standard cascading token extraction settings (Cookie -> Bearer Header).
func DefaultExtractConfig() ExtractConfig {
	return ExtractConfig{
		Sources:      []TokenSource{SourceCookie, SourceHeader},
		CookieName:   DefaultExtractCookieName,
		HeaderName:   DefaultExtractHeaderName,
		HeaderPrefix: DefaultExtractHeaderPrefix,
		QueryParam:   DefaultExtractQueryParam,
	}
}

// ExtractOption represents a functional option for customizing token extraction.
type ExtractOption func(*ExtractConfig)

// WithExtractCookie configures the cookie name to inspect during extraction.
func WithExtractCookie(name string) ExtractOption {
	return func(c *ExtractConfig) {
		if name != "" {
			c.CookieName = name
		}
	}
}

// WithExtractHeader configures a custom header name and optional prefix.
func WithExtractHeader(headerName, prefix string) ExtractOption {
	return func(c *ExtractConfig) {
		if headerName != "" {
			c.HeaderName = headerName
		}
		c.HeaderPrefix = prefix
	}
}

// WithExtractBearer configures standard "Authorization: Bearer <token>" extraction.
func WithExtractBearer() ExtractOption {
	return func(c *ExtractConfig) {
		c.HeaderName = DefaultExtractHeaderName
		c.HeaderPrefix = DefaultExtractHeaderPrefix
	}
}

// WithExtractQueryParam configures a query parameter name and activates SourceQuery in the search cascade.
func WithExtractQueryParam(paramName string) ExtractOption {
	return func(c *ExtractConfig) {
		if paramName != "" {
			c.QueryParam = paramName
		}
		hasQuery := false
		for _, s := range c.Sources {
			if s == SourceQuery {
				hasQuery = true
				break
			}
		}
		if !hasQuery {
			c.Sources = append(c.Sources, SourceQuery)
		}
	}
}

// WithSources explicitly overrides the extraction sources and their evaluation order.
func WithSources(sources ...TokenSource) ExtractOption {
	return func(c *ExtractConfig) {
		if len(sources) > 0 {
			c.Sources = make([]TokenSource, len(sources))
			copy(c.Sources, sources)
		}
	}
}

// ExtractToken inspects the given HTTP request and extracts an authentication token
// using the configured cascading strategy (default: Cookie -> Authorization: Bearer -> Query Param).
// Returns the raw token string, or ErrTokenNotFound if no token was located.
func ExtractToken(r *http.Request, opts ...ExtractOption) (string, error) {
	if r == nil {
		return "", ErrNilRequest
	}

	cfg := DefaultExtractConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	for _, src := range cfg.Sources {
		switch src {
		case SourceCookie:
			if cfg.CookieName != "" {
				if cookie, err := r.Cookie(cfg.CookieName); err == nil {
					val := strings.TrimSpace(cookie.Value)
					if val != "" {
						return val, nil
					}
				}
			}

		case SourceHeader:
			if cfg.HeaderName != "" {
				raw := strings.TrimSpace(r.Header.Get(cfg.HeaderName))
				if raw != "" {
					if cfg.HeaderPrefix == "" {
						return raw, nil
					}
					if len(raw) >= len(cfg.HeaderPrefix) &&
						strings.EqualFold(raw[:len(cfg.HeaderPrefix)], cfg.HeaderPrefix) {
						token := strings.TrimSpace(raw[len(cfg.HeaderPrefix):])
						if token != "" {
							return token, nil
						}
					}
				}
			}

		case SourceQuery:
			if cfg.QueryParam != "" && r.URL != nil {
				val := strings.TrimSpace(r.URL.Query().Get(cfg.QueryParam))
				if val != "" {
					return val, nil
				}
			}
		}
	}

	return "", ErrTokenNotFound
}
