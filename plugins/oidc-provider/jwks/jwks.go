package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"math/big"
)

// JWK represents a single public key in JWK format.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// FromRSAPublicKey converts an *rsa.PublicKey to a JWK.
func FromRSAPublicKey(pub *rsa.PublicKey, kid, alg string) JWK {
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	if len(eBytes) == 0 {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(pub.E))
		eBytes = buf
	}

	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: alg,
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}
