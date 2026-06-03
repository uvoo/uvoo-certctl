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

	"uvoo-certctl/internal/auth"
	"uvoo-certctl/internal/storage"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

func TestAdminDoctorBearerPendingByDefault(t *testing.T) {
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
		Audiences:     []string{"uvoo-certctl"},
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
		Principal:  "role:" + issuerURL + ":uvoo-certctl_admin",
		Permission: "doctor.read",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	token := signTestToken(t, signer, issuerURL, []string{"uvoo-certctl_admin"}, []string{"uvoo-certctl"})

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
	if !strings.Contains(rec.Body.String(), "pending local approval") {
		t.Fatalf("expected pending subject error, got %s", rec.Body.String())
	}

	store, err = storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	subjectRec, err := store.GetSubject(issuerURL, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if subjectRec.Status != storage.SubjectStatusPending {
		t.Fatalf("expected pending subject, got %s", subjectRec.Status)
	}
	if subjectRec.AuthCount < 1 {
		t.Fatalf("expected auth count to be recorded, got %d", subjectRec.AuthCount)
	}
}

func TestAdminDoctorAllowsApprovedBearerSubjectWithBinding(t *testing.T) {
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
		Audiences:     []string{"uvoo-certctl"},
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
		Principal:  "role:" + issuerURL + ":uvoo-certctl_admin",
		Permission: "doctor.read",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertSubjectSeen(storage.Subject{
		ID:       "subject-1",
		Issuer:   issuerURL,
		Subject:  "user-1",
		Status:   storage.SubjectStatusActive,
		Username: "alice",
		Email:    "alice@example.com",
		Roles:    []string{"uvoo-certctl_admin"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateSubjectApproval(issuerURL, "user-1", storage.SubjectStatusActive, []string{"admin"}, []string{"ops"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthzBinding(storage.AuthzBinding{
		ID:         "binding-2",
		Enabled:    true,
		Principal:  "local_role:admin",
		Permission: "metrics.read",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	token := signTestToken(t, signer, issuerURL, []string{"uvoo-certctl_admin"}, []string{"uvoo-certctl"})

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

func TestAdminDoctorAutoApprovesMatchingSubjectRule(t *testing.T) {
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
		Audiences:     []string{"uvoo-certctl"},
		SubjectClaim:  "sub",
		UsernameClaim: "preferred_username",
		EmailClaim:    "email",
		RolesClaims:   []string{"realm_access.roles"},
		GroupsClaims:  []string{"groups"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertSubjectAutoApprovalRule(storage.SubjectAutoApprovalRule{
		ID:          "rule-1",
		Name:        "example-users",
		Enabled:     true,
		Issuer:      issuerURL,
		EmailDomain: "example.com",
		LocalGroups: []string{"employees"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthzBinding(storage.AuthzBinding{
		ID:         "binding-1",
		Enabled:    true,
		Principal:  "local_group:employees",
		Permission: "doctor.read",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	token := signTestTokenWithClaims(t, signer, issuerURL, []string{"uvoo-certctl_viewer"}, []string{"uvoo-certctl"}, map[string]any{
		"email": "alice@example.com",
	})

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

	store, err = storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	subjectRec, err := store.GetSubject(issuerURL, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if subjectRec.Status != storage.SubjectStatusActive {
		t.Fatalf("expected auto-approved active subject, got %s", subjectRec.Status)
	}
	if !strings.Contains(strings.Join(subjectRec.LocalGroups, ","), "employees") {
		t.Fatalf("expected employees local group, got %+v", subjectRec.LocalGroups)
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
		Audiences:     []string{"uvoo-certctl"},
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

	token := signTestToken(t, signer, issuerURL, []string{"uvoo-certctl_viewer"}, []string{"uvoo-certctl"})

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

func TestAdminDoctorBearerForbiddenWhenSubjectDisabled(t *testing.T) {
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
		Audiences:     []string{"uvoo-certctl"},
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
		Principal:  "role:" + issuerURL + ":uvoo-certctl_admin",
		Permission: "doctor.read",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertSubjectSeen(storage.Subject{
		ID:       "subject-1",
		Issuer:   issuerURL,
		Subject:  "user-1",
		Status:   storage.SubjectStatusActive,
		Username: "alice",
		Email:    "alice@example.com",
		Roles:    []string{"uvoo-certctl_admin"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSubjectStatus(issuerURL, "user-1", storage.SubjectStatusDisabled); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	token := signTestToken(t, signer, issuerURL, []string{"uvoo-certctl_admin"}, []string{"uvoo-certctl"})

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
	if !strings.Contains(rec.Body.String(), "locally disabled") {
		t.Fatalf("expected disabled subject error, got %s", rec.Body.String())
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
	return signTestTokenWithClaims(t, signer, issuer, roles, audiences, nil)
}

func signTestTokenWithClaims(t *testing.T, signer jose.Signer, issuer string, roles []string, audiences []string, extra map[string]any) string {
	t.Helper()

	claims := map[string]any{
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"realm_access": map[string]any{
			"roles": roles,
		},
	}
	for key, value := range extra {
		claims[key] = value
	}
	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Issuer:    issuer,
		Subject:   "user-1",
		Audience:  josejwt.Audience(audiences),
		Expiry:    josejwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
		NotBefore: josejwt.NewNumericDate(time.Now().UTC().Add(-time.Minute)),
		IssuedAt:  josejwt.NewNumericDate(time.Now().UTC().Add(-time.Minute)),
	}).Claims(claims).Serialize()
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
