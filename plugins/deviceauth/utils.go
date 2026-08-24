package deviceauth

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"net/url"
	"strings"
)

// DefaultCharset contains human-friendly uppercase letters and numbers, excluding ambiguous characters (0, O, 1, I, L).
const DefaultCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// DefaultGenerateDeviceCode generates a cryptographically secure random hex device code string.
func DefaultGenerateDeviceCode(length int) (string, error) {
	if length <= 0 {
		length = 40
	}
	bytesNeeded := (length + 1) / 2
	b := make([]byte, bytesNeeded)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	res := hex.EncodeToString(b)
	if len(res) > length {
		res = res[:length]
	}
	return res, nil
}

// DefaultGenerateUserCode generates a cryptographically secure user verification code using DefaultCharset.
func DefaultGenerateUserCode(length int) (string, error) {
	if length <= 0 {
		length = 8
	}

	charsetLen := big.NewInt(int64(len(DefaultCharset)))
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		buf[i] = DefaultCharset[idx.Int64()]
	}

	// Insert hyphen in the middle for readability if length is >= 6
	if length >= 6 {
		mid := length / 2
		return string(buf[:mid]) + "-" + string(buf[mid:]), nil
	}

	return string(buf), nil
}

// NormalizeUserCode strips spaces, hyphens, and converts the input string to uppercase.
func NormalizeUserCode(code string) string {
	cleaned := strings.ReplaceAll(code, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	return strings.ToUpper(strings.TrimSpace(cleaned))
}

// BuildVerificationURIs constructs the standard verification_uri and verification_uri_complete URLs.
func BuildVerificationURIs(baseURI, customURI, userCode string) (uri string, uriComplete string) {
	root := strings.TrimSpace(customURI)
	if root == "" {
		root = strings.TrimSpace(baseURI)
	}
	if root == "" {
		root = "/device"
	}

	uri = root

	// Parse URI to properly append query parameters
	parsed, err := url.Parse(root)
	if err == nil {
		q := parsed.Query()
		q.Set("user_code", userCode)
		parsed.RawQuery = q.Encode()
		uriComplete = parsed.String()
	} else {
		if strings.Contains(root, "?") {
			uriComplete = root + "&user_code=" + url.QueryEscape(userCode)
		} else {
			uriComplete = root + "?user_code=" + url.QueryEscape(userCode)
		}
	}

	return uri, uriComplete
}
