package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServeHTTPAllowsConfiguredNACL(t *testing.T) {
	srv := New(Config{
		AllowCIDRs: []string{"10.0.0.0/8"},
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "10.20.30.40:1234"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestServeHTTPDeniesRemoteOutsideNACL(t *testing.T) {
	srv := New(Config{
		AllowCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"},
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not allowed by nacl") {
		t.Fatalf("expected nacl error, got %s", rec.Body.String())
	}
}

func TestServeHTTPAllowsConfiguredIPv6NACL(t *testing.T) {
	srv := New(Config{
		AllowCIDRs: []string{"fc00::/7"},
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "[fd12:3456:789a::10]:1234"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestServeHTTPRejectsInvalidNACLConfig(t *testing.T) {
	srv := New(Config{
		AllowCIDRs: []string{"not-a-cidr"},
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestValidateTLSFiles(t *testing.T) {
	if err := validateTLSFiles("", "server.key"); err == nil {
		t.Fatal("expected missing cert file to fail")
	}
	if err := validateTLSFiles("server.crt", ""); err == nil {
		t.Fatal("expected missing key file to fail")
	}
	if err := validateTLSFiles("server.crt", "server.key"); err != nil {
		t.Fatalf("expected tls config to validate, got %v", err)
	}
}
