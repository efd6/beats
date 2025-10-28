package dpop

import (
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
    "errors"
    "net/http"

    "golang.org/x/oauth2"
)

// NewTokenClient builds an *http.Client to be used by oauth2.Config or clientcredentials.Config
// when exchanging code/client_credentials to get an access token.
// This client sends DPoP proofs to the token endpoint.
func NewTokenClient(ctx context.Context, privateKey interface{}, base *http.Client) (*http.Client, error) {
	pg, err := NewProofGenerator(privateKey)
	if err != nil {
		return nil, err
	}
	tr := &TokenTransport{ProofGen: pg}
	if base != nil && base.Transport != nil {
		tr.Base = base.Transport
	}
	client := &http.Client{Transport: tr}
	return client, nil
}

// NewResourceClient builds an *http.Client that wraps oauth2.TokenSource and sends DPoP proofs
// and Authorization: DPoP <access_token> to protected resource endpoints.
func NewResourceClient(ctx context.Context, privateKey interface{}, ts oauth2.TokenSource, base *http.Client) (*http.Client, error) {
	if ts == nil {
		return nil, errors.New("token source is required")
	}
	pg, err := NewProofGenerator(privateKey)
	if err != nil {
		return nil, err
	}
	tr := &Transport{TokenSource: ts, ProofGen: pg}
	if base != nil && base.Transport != nil {
		tr.Base = base.Transport
	}
	client := &http.Client{Transport: tr}
	return client, nil
}

// GenerateECDSAP256Key creates a fresh ECDSA P-256 private key for DPoP.
func GenerateECDSAP256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateRSAPrivateKey creates a fresh RSA private key suitable for RS256.
func GenerateRSAPrivateKey(bits int) (*rsa.PrivateKey, error) {
	if bits <= 0 {
		bits = 2048
	}
	return rsa.GenerateKey(rand.Reader, bits)
}
