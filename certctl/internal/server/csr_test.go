package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"certctl/internal/storage"
)

func TestCSRSubmitAndPickupFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	srv := New(Config{
		DBPath:            dbPath,
		Listen:            ":0",
		CSRSubmitPassword: "submit-secret",
	})

	req := newCSRSubmitRequest(t, storage.CertKindPublic, "submit-secret", mustCreateServerTestCSR(t, "api.example.com", []string{"api.example.com"}))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var submitResp struct {
		ID          string `json:"id"`
		PickupToken string `json:"pickup_token"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &submitResp); err != nil {
		t.Fatal(err)
	}
	if submitResp.ID == "" || submitResp.PickupToken == "" || submitResp.Status != storage.CSRStatusPending {
		t.Fatalf("unexpected submit response: %+v", submitResp)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/csr-requests/"+submitResp.ID+"?pickup_token="+submitResp.PickupToken, nil)
	statusRec := httptest.NewRecorder()
	srv.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK || !strings.Contains(statusRec.Body.String(), `"status":"pending"`) {
		t.Fatalf("expected pending status response, got %d: %s", statusRec.Code, statusRec.Body.String())
	}

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(storage.PublicCert{
		ID:         "pub-1",
		CommonName: "api.example.com",
		SANsCSV:    "api.example.com",
		SANsHash:   "hash-1",
		CertPEM:    []byte("issued-cert"),
		KeyPEM:     nil,
		Provider:   "godaddy",
		NotBefore:  time.Now().UTC().Add(-time.Hour),
		NotAfter:   time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkCSRRequestIssued(submitResp.ID, "pub-1", "approved"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	issuedReq := httptest.NewRequest(http.MethodGet, "/csr-requests/"+submitResp.ID, nil)
	issuedReq.Header.Set("X-Pickup-Token", submitResp.PickupToken)
	issuedRec := httptest.NewRecorder()
	srv.ServeHTTP(issuedRec, issuedReq)
	if issuedRec.Code != http.StatusOK || !strings.Contains(issuedRec.Body.String(), `"certificate_pem":"issued-cert"`) {
		t.Fatalf("expected issued certificate response, got %d: %s", issuedRec.Code, issuedRec.Body.String())
	}
}

func TestCSRRejectAndPickupFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	srv := New(Config{
		DBPath:            dbPath,
		Listen:            ":0",
		CSRSubmitPassword: "submit-secret",
	})

	req := newCSRSubmitRequest(t, storage.CertKindPrivate, "submit-secret", mustCreateServerTestCSR(t, "api.internal", []string{"api.internal"}))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var submitResp struct {
		ID          string `json:"id"`
		PickupToken string `json:"pickup_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &submitResp); err != nil {
		t.Fatal(err)
	}

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RejectCSRRequest(submitResp.ID, "unable to verify requester"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/csr-requests/"+submitResp.ID+"?pickup_token="+submitResp.PickupToken, nil)
	statusRec := httptest.NewRecorder()
	srv.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", statusRec.Code, statusRec.Body.String())
	}
	body := statusRec.Body.String()
	if !strings.Contains(body, `"status":"rejected"`) || !strings.Contains(body, `"decision_note":"unable to verify requester"`) {
		t.Fatalf("expected rejected status payload, got %s", body)
	}
}

func TestCSRSubmitRateLimited(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	srv := New(Config{
		DBPath:            dbPath,
		Listen:            ":0",
		CSRSubmitPassword: "submit-secret",
		CSRMinInterval:    time.Hour,
	})

	req1 := newCSRSubmitRequest(t, storage.CertKindPublic, "submit-secret", mustCreateServerTestCSR(t, "api.example.com", []string{"api.example.com"}))
	req1.RemoteAddr = "203.0.113.10:1234"
	rec1 := httptest.NewRecorder()
	srv.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusCreated {
		t.Fatalf("expected first submit to succeed, got %d: %s", rec1.Code, rec1.Body.String())
	}

	req2 := newCSRSubmitRequest(t, storage.CertKindPublic, "submit-secret", mustCreateServerTestCSR(t, "api2.example.com", []string{"api2.example.com"}))
	req2.RemoteAddr = "203.0.113.10:5678"
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}
}

func TestCSRSubmitBodyTooLarge(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	srv := New(Config{
		DBPath:            dbPath,
		Listen:            ":0",
		CSRSubmitPassword: "submit-secret",
		CSRMaxBodyBytes:   128,
		CSRMinInterval:    time.Millisecond,
	})

	var large strings.Builder
	for i := 0; i < 1024; i++ {
		large.WriteString("A")
	}
	req := httptest.NewRequest(http.MethodPost, "/csr-requests", strings.NewReader(`{"kind":"public","submit_password":"submit-secret","csr_pem":"`+large.String()+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
}

func newCSRSubmitRequest(t *testing.T, kind, submitPassword string, csr []byte) *http.Request {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("kind", kind)
	_ = writer.WriteField("submit_password", submitPassword)
	_ = writer.WriteField("requester_name", "Jane Doe")
	part, err := writer.CreateFormFile("csr", "server.csr")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(csr); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/csr-requests", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func mustCreateServerTestCSR(t *testing.T, commonName string, dnsNames []string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
