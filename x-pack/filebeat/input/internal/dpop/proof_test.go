package dpop

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func decodePart(t *testing.T, part string, v interface{}) {
	b, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestBuildProofIncludesRequiredClaims(t *testing.T) {
	key, err := GenerateECDSAP256Key()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	pg, err := NewProofGenerator(key)
	if err != nil {
		t.Fatalf("proof gen: %v", err)
	}
	now := time.Now().Unix()
	proof, err := pg.BuildProof(context.Background(), http.MethodGet, "https://api.example.com/path?q=1#frag", ProofOptions{})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	var header map[string]interface{}
	decodePart(t, parts[0], &header)
	if header["typ"] != "dpop+jwt" {
		t.Fatalf("wrong typ: %v", header["typ"])
	}
	if header["alg"] != "ES256" {
		t.Fatalf("wrong alg: %v", header["alg"])
	}
	if _, ok := header["jwk"].(map[string]interface{}); !ok {
		t.Fatalf("missing jwk")
	}
	var claims map[string]interface{}
	decodePart(t, parts[1], &claims)
	if claims["htm"] != "GET" {
		t.Fatalf("wrong htm: %v", claims["htm"])
	}
	if claims["htu"] != "https://api.example.com/path?q=1" {
		t.Fatalf("wrong htu: %v", claims["htu"])
	}
	if _, ok := claims["jti"].(string); !ok {
		t.Fatalf("missing jti")
	}
	if iat, ok := claims["iat"].(float64); !ok || int64(iat) < now-5 || int64(iat) > now+5 {
		t.Fatalf("iat out of range: %v", claims["iat"])
	}
}

type staticTokenSource struct{ token *oauth2.Token }

func (s staticTokenSource) Token() (*oauth2.Token, error) { return s.token, nil }

func TestResourceTransportSetsHeadersAndAth(t *testing.T) {
	key, err := GenerateECDSAP256Key()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	accessToken := "test-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "DPoP "+accessToken {
			w.WriteHeader(400)
			return
		}
		proof := r.Header.Get("DPoP")
		if proof == "" {
			w.WriteHeader(400)
			return
		}
		parts := strings.Split(proof, ".")
		var claims map[string]interface{}
		decodePart(t, parts[1], &claims)
		if _, ok := claims["ath"].(string); !ok {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	pg, _ := NewProofGenerator(key)
	ts := staticTokenSource{token: &oauth2.Token{AccessToken: accessToken, TokenType: "DPoP"}}
	cl := &http.Client{Transport: &Transport{TokenSource: ts, ProofGen: pg}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/resource", nil)
	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", res.StatusCode)
	}
}

func TestTokenTransportRetriesWithNonce(t *testing.T) {
	key, _ := GenerateECDSAP256Key()
	var first = true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if first {
			first = false
			w.Header().Set("DPoP-Nonce", "abc123")
			w.WriteHeader(401)
			return
		}
		proof := r.Header.Get("DPoP")
		parts := strings.Split(proof, ".")
		var claims map[string]interface{}
		decodePart(t, parts[1], &claims)
		if claims["nonce"] != "abc123" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	pg, _ := NewProofGenerator(key)
	cl := &http.Client{Transport: &TokenTransport{ProofGen: pg}}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", nil)
	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", res.StatusCode)
	}
}

func TestKeyHelpers(t *testing.T) {
	if k, err := GenerateECDSAP256Key(); err != nil || k.Curve != elliptic.P256() {
		t.Fatalf("ecdsa key: %v", err)
	}
	if k, err := GenerateRSAPrivateKey(1024); err != nil || k.N.BitLen() < 1024 {
		t.Fatalf("rsa key: %v", err)
	}
}
