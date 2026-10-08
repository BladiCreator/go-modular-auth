package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWK represents a single JSON Web Key per RFC 7517.
type JWK struct {
	// Kty is the key type: RSA, EC, or OKP.
	Kty string `json:"kty"`

	// Use is the intended public key use: "sig".
	Use string `json:"use,omitempty"`

	// Kid is the key identifier.
	Kid string `json:"kid,omitempty"`

	// Alg is the algorithm intended for use with the key.
	Alg string `json:"alg,omitempty"`

	// Crv is the cryptographic curve for EC or OKP keys (e.g., "P-256", "Ed25519").
	Crv string `json:"crv,omitempty"`

	// X is the x coordinate for EC keys, or public key for OKP keys (base64url-encoded).
	X string `json:"x,omitempty"`

	// Y is the y coordinate for EC keys (base64url-encoded).
	Y string `json:"y,omitempty"`

	// N is the RSA modulus (base64url-encoded).
	N string `json:"n,omitempty"`

	// E is the RSA public exponent (base64url-encoded).
	E string `json:"e,omitempty"`
}

// JWKS represents a JSON Web Key Set per RFC 7517.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JSON serializes the JWKS to formatted JSON bytes.
func (j *JWKS) JSON() ([]byte, error) {
	return json.Marshal(j)
}

// BuildJWKS generates a JWKS from the given KeyManager, exporting only asymmetric public keys.
// Symmetric HMAC keys are strictly excluded to prevent secret disclosure.
func BuildJWKS(km KeyManager) (*JWKS, error) {
	if km == nil {
		return &JWKS{Keys: []JWK{}}, nil
	}

	keys := km.ListKeys()
	jwks := &JWKS{
		Keys: make([]JWK, 0, len(keys)),
	}

	for _, k := range keys {
		// Never export symmetric keys
		if k.Algorithm.IsSymmetric() {
			continue
		}

		jwk, err := KeyToJWK(k)
		if err != nil {
			return nil, fmt.Errorf("jwt: converting key %s to JWK: %w", k.ID, err)
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}

	return jwks, nil
}

// KeyToJWK converts an asymmetric Key into an RFC 7517 JWK.
func KeyToJWK(k Key) (JWK, error) {
	if k.Algorithm.IsSymmetric() {
		return JWK{}, fmt.Errorf("%w: symmetric keys cannot be converted to public JWK", ErrInvalidKey)
	}

	switch pub := k.PublicKey.(type) {
	case *rsa.PublicKey:
		// Encode E
		eBytes := bigIntToBytes(big.NewInt(int64(pub.E)))
		return JWK{
			Kty: "RSA",
			Use: k.Use,
			Kid: k.ID,
			Alg: string(k.Algorithm),
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		}, nil

	case *ecdsa.PublicKey:
		crvName, byteSize, err := curveJWKInfo(pub.Curve)
		if err != nil {
			return JWK{}, err
		}
		xBytes := padBytes(pub.X.Bytes(), byteSize)
		yBytes := padBytes(pub.Y.Bytes(), byteSize)

		return JWK{
			Kty: "EC",
			Use: k.Use,
			Kid: k.ID,
			Alg: string(k.Algorithm),
			Crv: crvName,
			X:   base64.RawURLEncoding.EncodeToString(xBytes),
			Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		}, nil

	case ed25519.PublicKey:
		return JWK{
			Kty: "OKP",
			Use: k.Use,
			Kid: k.ID,
			Alg: string(k.Algorithm),
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
		}, nil

	default:
		return JWK{}, fmt.Errorf("%w: unsupported public key type %T", ErrInvalidKey, k.PublicKey)
	}
}

func curveJWKInfo(curve elliptic.Curve) (string, int, error) {
	switch curve {
	case elliptic.P256():
		return "P-256", 32, nil
	case elliptic.P384():
		return "P-384", 48, nil
	case elliptic.P521():
		return "P-521", 66, nil
	default:
		return "", 0, fmt.Errorf("%w: unsupported elliptic curve", ErrInvalidKey)
	}
}

func padBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

func bigIntToBytes(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) == 0 {
		return []byte{0}
	}
	return b
}

func uint64ToBigEndian(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	// strip leading zeroes
	for len(buf) > 1 && buf[0] == 0 {
		buf = buf[1:]
	}
	return buf
}
