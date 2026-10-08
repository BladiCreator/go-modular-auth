package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type tokenHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

func encodeToken(header tokenHeader, claims Claims, key Key) (string, error) {
	if header.Alg == "" || header.Alg == "none" {
		return "", ErrUnsignedTokenNotAllowed
	}
	if !key.CanSign() {
		return "", fmt.Errorf("%w: key %s cannot sign", ErrInvalidKey, key.ID)
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("%w: failed to marshal header: %v", ErrInvalidToken, err)
	}

	claimsJSON, err := claims.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("%w: failed to marshal claims: %v", ErrInvalidToken, err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + payloadB64

	sig, err := sign(Algorithm(header.Alg), key.PrivateKey, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("jwt: signing failed: %w", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

type parsedToken struct {
	header       tokenHeader
	claims       Claims
	signingInput []byte
	signature    []byte
}

func parseToken(tokenString string) (*parsedToken, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 dot-separated segments, got %d", ErrInvalidToken, len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header base64 decode: %v", ErrInvalidToken, err)
	}

	var header tokenHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: header json unmarshal: %v", ErrInvalidToken, err)
	}

	// Strictly reject unsigned tokens
	if strings.ToLower(header.Alg) == "none" || strings.TrimSpace(header.Alg) == "" {
		return nil, ErrUnsignedTokenNotAllowed
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload base64 decode: %v", ErrInvalidToken, err)
	}

	var claims Claims
	if err := claims.UnmarshalJSON(payloadBytes); err != nil {
		return nil, fmt.Errorf("%w: payload json unmarshal: %v", ErrInvalidToken, err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature base64 decode: %v", ErrInvalidToken, err)
	}
	if len(sigBytes) == 0 {
		return nil, ErrUnsignedTokenNotAllowed
	}

	signingInput := parts[0] + "." + parts[1]

	return &parsedToken{
		header:       header,
		claims:       claims,
		signingInput: []byte(signingInput),
		signature:    sigBytes,
	}, nil
}
