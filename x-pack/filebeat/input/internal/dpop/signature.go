package dpop

import (
    "crypto/sha256"
    "encoding/base64"
)

// Helpers to hash and sign DPoP proof inputs.

// sha256Base64URL returns the base64url (no padding) encoding of the SHA-256
// digest of the provided string.
func sha256Base64URL(data string) (string, error) {
	h := sha256.Sum256([]byte(data))
	enc := base64RawURLEncode(h[:])
	return enc, nil
}

// base64RawURLEncode encodes bytes using base64url without padding.
func base64RawURLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// signECDSA creates an ES256 signature over data (with SHA-256) and returns
// the raw (r || s) concatenation, as required by JOSE for ES256.
// Signing is delegated to the jwt/v5 library in proof.go
