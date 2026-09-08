package httpauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetClientIP_XForwardedFor(t *testing.T) {
	t.Run("multiple IPs in XFF returns first valid IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")

		ip := GetClientIP(req)
		if ip != "203.0.113.195" {
			t.Errorf("expected 203.0.113.195, got %q", ip)
		}
	})

	t.Run("skips invalid candidate in XFF to pick first valid IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "unknown, 198.51.100.42")

		ip := GetClientIP(req)
		if ip != "198.51.100.42" {
			t.Errorf("expected 198.51.100.42, got %q", ip)
		}
	})
}

func TestGetClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "198.51.100.1")

	ip := GetClientIP(req)
	if ip != "198.51.100.1" {
		t.Errorf("expected 198.51.100.1, got %q", ip)
	}
}

func TestGetClientIP_RemoteAddr(t *testing.T) {
	t.Run("IPv4 with port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.50:52341"

		ip := GetClientIP(req)
		if ip != "192.168.1.50" {
			t.Errorf("expected 192.168.1.50, got %q", ip)
		}
	})

	t.Run("IPv6 with port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "[2001:db8::1]:8080"

		ip := GetClientIP(req)
		if ip != "2001:db8::1" {
			t.Errorf("expected 2001:db8::1, got %q", ip)
		}
	})

	t.Run("IPv4 without port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1"

		ip := GetClientIP(req)
		if ip != "10.0.0.1" {
			t.Errorf("expected 10.0.0.1, got %q", ip)
		}
	})
}

func TestGetClientIP_NilAndInvalid(t *testing.T) {
	if ip := GetClientIP(nil); ip != "" {
		t.Errorf("expected empty string for nil request, got %q", ip)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "invalid-address"
	if ip := GetClientIP(req); ip != "" {
		t.Errorf("expected empty string for invalid address, got %q", ip)
	}
}

func TestGetUserAgent(t *testing.T) {
	t.Run("valid user agent string", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

		ua := GetUserAgent(req)
		if ua != "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" {
			t.Errorf("unexpected user agent: %q", ua)
		}
	})

	t.Run("nil request returns empty string", func(t *testing.T) {
		if ua := GetUserAgent(nil); ua != "" {
			t.Errorf("expected empty string for nil request, got %q", ua)
		}
	})
}
