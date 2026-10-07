// Package secure contains the cryptographic primitives shared by the core:
// random identifiers, opaque secret tokens and their storage representation.
package secure

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

// TokenBytes is the amount of entropy (in bytes) used for opaque secret tokens.
const TokenBytes = 32

// IDBytes is the amount of entropy (in bytes) used for entity identifiers.
const IDBytes = 16

// NewID returns a random, URL-safe, hex encoded identifier.
func NewID() string {
	return hex.EncodeToString(randomBytes(IDBytes))
}

// NewToken returns a random, URL-safe opaque secret token. The plaintext token
// must only ever be handed to the client; persist HashToken(token) instead.
func NewToken() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(TokenBytes))
}

// randomBytes reads n bytes from crypto/rand. Since Go 1.24 rand.Read never
// returns an error (it crashes the program on irrecoverable failures).
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// HashToken derives the storage/lookup representation of an opaque token.
//
// Tokens carry 256 bits of entropy, so a fast cryptographic hash is
// sufficient: brute force against the hash is infeasible, and lookups stay O(1).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Equal compares two strings in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
