package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// ProofOptions holds optional values like nonce and access token hash (ath).
// 'ath' should be the base64url-encoded SHA256 of the access token bytes.
// If Nonce is provided, it will be set in the DPoP proof as 'nonce'.
// If AccessToken is provided, we will compute the SHA-256 hash and set 'ath'.

type ProofOptions struct {
	Nonce       string
	AccessToken string
}

// ProofGenerator builds DPoP proofs for requests.
// It supports ECDSA P-256 and RSA private keys.

type ProofGenerator struct {
	privateKey interface{}
	jwk        map[string]interface{}
	alg        keyAlgorithm
}

// NewProofGenerator creates a new ProofGenerator.
func NewProofGenerator(privateKey interface{}) (*ProofGenerator, error) {
	jwk, alg, err := buildJWKAndAlg(privateKey)
	if err != nil {
		return nil, err
	}
	return &ProofGenerator{privateKey: privateKey, jwk: jwk, alg: alg}, nil
}

// BuildProof produces a compact JWS string containing the DPoP proof for the given HTTP method and URL.
// BuildProof constructs a signed DPoP proof JWT for the given HTTP method and
// URL. The URL fragment, if present, is stripped per RFC. Optional fields like
// nonce and access token hash (ath) are included when provided via opts.
func (g *ProofGenerator) BuildProof(ctx context.Context, method, url string, opts ProofOptions) (string, error) {
	if g == nil || g.privateKey == nil {
		return "", errors.New("nil proof generator or key")
	}
	htu := url
	if i := strings.Index(htu, "#"); i >= 0 { // strip fragment
		htu = htu[:i]
	}
	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": string(g.alg),
		"jwk": g.jwk,
	}
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"htu": htu,
		"htm": strings.ToUpper(method),
		"iat": now,
		"jti": randomJTI(),
	}
	if opts.Nonce != "" {
		claims["nonce"] = opts.Nonce
	}
	if opts.AccessToken != "" {
		h, err := sha256Base64URL(opts.AccessToken)
		if err != nil {
			return "", err
		}
		claims["ath"] = h
	}
	return signJWS(g.privateKey, header, claims)
}

// randomJTI returns a URL-safe, random identifier for the "jti" claim.
func randomJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// signJWS produces a compact JWS string by signing the given header and claims
// with the provided private key, using the algorithm implied by the key type.
func signJWS(privateKey interface{}, header, claims map[string]interface{}) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encHeader := base64.RawURLEncoding.EncodeToString(hb)
	encPayload := base64.RawURLEncoding.EncodeToString(cb)
	unsigned := encHeader + "." + encPayload

	sig, err := signDetached(privateKey, unsigned)
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// signDetached signs the given data using the appropriate algorithm for
// the provided key and returns the raw signature bytes.
func signDetached(privateKey interface{}, data string) ([]byte, error) {
	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return signECDSA(k, []byte(data))
	case *rsa.PrivateKey:
		return signRSA(k, []byte(data))
	default:
		return nil, errors.New("unsupported private key type for signing")
	}
}

// Transport decorates an underlying RoundTripper to add DPoP proofs and bearer auth.
// It uses the provided TokenSource for access tokens and adds both Authorization and DPoP headers.

// Transport is an http.RoundTripper that adds DPoP proofs and Authorization
// headers (Authorization: DPoP <access_token>) to outgoing requests using the
// provided oauth2.TokenSource. It retries once on a DPoP-Nonce challenge.
type Transport struct {
	Base        http.RoundTripper
	TokenSource oauth2.TokenSource
	ProofGen    *ProofGenerator
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	if t.TokenSource == nil || t.ProofGen == nil {
		return nil, errors.New("dpop transport requires TokenSource and ProofGenerator")
	}
	tok, err := t.TokenSource.Token()
	if err != nil {
		return nil, err
	}
	// clone the request to avoid mutating the original
	r := req.Clone(req.Context())
	if tok.AccessToken != "" {
		r.Header.Set("Authorization", "DPoP "+tok.AccessToken)
	}
	proof, err := t.ProofGen.BuildProof(req.Context(), req.Method, req.URL.String(), ProofOptions{AccessToken: tok.AccessToken})
	if err != nil {
		return nil, err
	}
	r.Header.Set("DPoP", proof)
	resp, err := base.RoundTrip(r)
	if err != nil {
		return resp, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest || resp.StatusCode == 429 {
		// Retry once if DPoP-Nonce provided
		if nonce := resp.Header.Get("DPoP-Nonce"); nonce != "" {
			_ = resp.Body.Close()
			proof, err = t.ProofGen.BuildProof(req.Context(), req.Method, req.URL.String(), ProofOptions{AccessToken: tok.AccessToken, Nonce: nonce})
			if err != nil {
				return nil, err
			}
			r2 := req.Clone(req.Context())
			if tok.AccessToken != "" {
				r2.Header.Set("Authorization", "DPoP "+tok.AccessToken)
			}
			r2.Header.Set("DPoP", proof)
			return base.RoundTrip(r2)
		}
	}
	return resp, nil
}
