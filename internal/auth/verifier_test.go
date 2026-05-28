package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"certctl/internal/storage"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

func TestVerifierCheckIssuerAndRequiredClaims(t *testing.T) {
	issuerURL, signer, jwks := newVerifierTestIssuer(t)
	verifier := NewVerifierWithClient(newVerifierTestHTTPClient(t, issuerURL, jwks))

	result, err := verifier.CheckIssuer(context.Background(), storage.AuthIssuer{
		Issuer:       issuerURL,
		DiscoveryURL: issuerURL + "/.well-known/openid-configuration",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.JWKSURL != issuerURL+"/jwks" || result.KeyCount != 1 {
		t.Fatalf("unexpected issuer check result: %+v", result)
	}

	token := signVerifierTestToken(t, signer, issuerURL, map[string]any{
		"azp": "certctl-cli",
	}, []string{"certctl"})
	identity, err := verifier.Verify(context.Background(), token, []storage.AuthIssuer{
		{
			ID:             "issuer-1",
			Name:           "local",
			Enabled:        true,
			Issuer:         issuerURL,
			Audiences:      []string{"certctl"},
			RequiredClaims: map[string]string{"azp": "certctl-cli"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "user-1" {
		t.Fatalf("unexpected identity: %+v", identity)
	}

	_, err = verifier.Verify(context.Background(), token, []storage.AuthIssuer{
		{
			ID:             "issuer-1",
			Name:           "local",
			Enabled:        true,
			Issuer:         issuerURL,
			Audiences:      []string{"certctl"},
			RequiredClaims: map[string]string{"azp": "other-client"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "required claim azp") {
		t.Fatalf("expected required claim error, got %v", err)
	}
}

func TestInspectTokenReturnsIssuerAndAudience(t *testing.T) {
	issuerURL, signer, _ := newVerifierTestIssuer(t)
	token := signVerifierTestToken(t, signer, issuerURL, nil, []string{"certctl", "metrics"})
	inspection, err := InspectToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Issuer != issuerURL || inspection.Subject != "user-1" {
		t.Fatalf("unexpected inspection: %+v", inspection)
	}
	if len(inspection.Audiences) != 2 {
		t.Fatalf("unexpected audiences: %+v", inspection.Audiences)
	}
}

func newVerifierTestIssuer(t *testing.T) (string, jose.Signer, jose.JSONWebKeySet) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     "test-key-1",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	issuerURL := "https://issuer.example.test"
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:       privateKey,
			KeyID:     jwk.KeyID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return issuerURL, signer, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk.Public()}}
}

func signVerifierTestToken(t *testing.T, signer jose.Signer, issuer string, extraClaims map[string]any, audiences []string) string {
	t.Helper()

	builder := josejwt.Signed(signer).Claims(josejwt.Claims{
		Issuer:    issuer,
		Subject:   "user-1",
		Audience:  josejwt.Audience(audiences),
		Expiry:    josejwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
		NotBefore: josejwt.NewNumericDate(time.Now().UTC().Add(-time.Minute)),
		IssuedAt:  josejwt.NewNumericDate(time.Now().UTC().Add(-time.Minute)),
	})
	if extraClaims != nil {
		builder = builder.Claims(extraClaims)
	}
	token, err := builder.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func newVerifierTestHTTPClient(t *testing.T, issuerURL string, jwks jose.JSONWebKeySet) *http.Client {
	t.Helper()

	discoveryBody, err := json.Marshal(map[string]any{
		"jwks_uri": issuerURL + "/jwks",
	})
	if err != nil {
		t.Fatal(err)
	}
	jwksBody, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: verifierRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case issuerURL + "/.well-known/openid-configuration":
				return verifierJSONResponse(discoveryBody), nil
			case issuerURL + "/jwks":
				return verifierJSONResponse(jwksBody), nil
			default:
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
					Header:     make(http.Header),
				}, nil
			}
		}),
	}
}

type verifierRoundTripFunc func(req *http.Request) (*http.Response, error)

func (fn verifierRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func verifierJSONResponse(body []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}
}
