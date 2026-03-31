package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"certctl/internal/auth"
	"certctl/internal/storage"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

func TestAdminDoctorAllowsBearerTokenWithBinding(t *testing.T) {
	issuerURL, signer, jwks := newTestOIDCIssuer(t)

	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAuthIssuer(storage.AuthIssuer{
		ID:            "issuer-1",
		Name:          "local-keycloak",
		Enabled:       true,
		Issuer:        issuerURL,
		Audiences:     []string{"certctl"},
		SubjectClaim:  "sub",
		UsernameClaim: "preferred_username",
		EmailClaim:    "email",
		RolesClaims:   []string{"realm_access.roles"},
		GroupsClaims:  []string{"groups"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthzBinding(storage.AuthzBinding{
		ID:         "binding-1",
		Enabled:    true,
		Principal:  "role:" + issuerURL + ":certctl_admin",
		Permission: "doctor.read",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	token := signTestToken(t, signer, issuerURL, []string{"certctl_admin"}, []string{"certctl"})

	srv := New(Config{
		DBPath:        dbPath,
		AdminWarnDays: 30,
	})
	srv.authVerifier = auth.NewVerifierWithClient(newTestOIDCHTTPClient(t, issuerURL, jwks))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/doctor", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("expected doctor ok response, got %s", rec.Body.String())
	}
}

func TestAdminDoctorBearerForbiddenWithoutBinding(t *testing.T) {
	issuerURL, signer, jwks := newTestOIDCIssuer(t)

	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAuthIssuer(storage.AuthIssuer{
		ID:            "issuer-1",
		Name:          "local-keycloak",
		Enabled:       true,
		Issuer:        issuerURL,
		Audiences:     []string{"certctl"},
		SubjectClaim:  "sub",
		UsernameClaim: "preferred_username",
		EmailClaim:    "email",
		RolesClaims:   []string{"realm_access.roles"},
		GroupsClaims:  []string{"groups"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	token := signTestToken(t, signer, issuerURL, []string{"certctl_viewer"}, []string{"certctl"})

	srv := New(Config{
		DBPath:        dbPath,
		AdminWarnDays: 30,
	})
	srv.authVerifier = auth.NewVerifierWithClient(newTestOIDCHTTPClient(t, issuerURL, jwks))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/doctor", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func newTestOIDCIssuer(t *testing.T) (string, jose.Signer, jose.JSONWebKeySet) {
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
	_ = jwk
	return issuerURL, signer, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk.Public()}}
}

func signTestToken(t *testing.T, signer jose.Signer, issuer string, roles []string, audiences []string) string {
	t.Helper()

	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Issuer:    issuer,
		Subject:   "user-1",
		Audience:  josejwt.Audience(audiences),
		Expiry:    josejwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
		NotBefore: josejwt.NewNumericDate(time.Now().UTC().Add(-time.Minute)),
		IssuedAt:  josejwt.NewNumericDate(time.Now().UTC().Add(-time.Minute)),
	}).Claims(map[string]any{
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"realm_access": map[string]any{
			"roles": roles,
		},
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func newTestOIDCHTTPClient(t *testing.T, issuerURL string, jwks jose.JSONWebKeySet) *http.Client {
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
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case issuerURL + "/.well-known/openid-configuration":
				return jsonHTTPResponse(discoveryBody), nil
			case issuerURL + "/jwks":
				return jsonHTTPResponse(jwksBody), nil
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

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func jsonHTTPResponse(body []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}
}
