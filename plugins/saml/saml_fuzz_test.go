package saml

import (
	"testing"
	"time"
)

func FuzzParseResponse(f *testing.F) {
	// Seed corpus with XML fragments and edge cases
	f.Add("<Response></Response>")
	f.Add("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><Response>&xxe;</Response>")
	f.Add("<Response><Assertion><Issuer>https://idp.example.com</Issuer></Assertion></Response>")
	f.Add("")
	f.Add("not-xml-at-all")
	f.Add("PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzYW1scDpSZXNwb25zZSB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIi8+")

	cfg := &IdPConfig{
		EntityID: "https://idp.example.com",
		SSOURL:   "https://idp.example.com/sso",
	}

	f.Fuzz(func(t *testing.T, data string) {
		_ = ExtractIssuer(data)
		_ = ExtractInResponseTo(data)
		_, _ = ParseAndVerifyResponse(data, cfg, "https://sp.example.com", "https://sp.example.com/acs", time.Now())
	})
}
