package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"uvoo-certctl/internal/ops"
	"uvoo-certctl/internal/storage"
)

func TestAdminDoctorRequiresAuth(t *testing.T) {
	srv := New(Config{
		DBPath:        filepath.Join(t.TempDir(), "certs.db"),
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
		AdminWarnDays: 30,
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/doctor", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("expected WWW-Authenticate header, got %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestAdminEffectiveAuthzForBasicAdmin(t *testing.T) {
	srv := New(Config{
		DBPath:        filepath.Join(t.TempDir(), "certs.db"),
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/effective-authz", nil)
	req.SetBasicAuth("admin", "admin-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"superuser":true`) || !strings.Contains(body, `"effective_permissions":["*"]`) {
		t.Fatalf("expected effective authz payload, got %s", body)
	}
}

func TestAdminAuthDoctorFiltersFindings(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthzBinding(storage.AuthzBinding{
		ID:         "binding-1",
		Enabled:    true,
		Principal:  "role:https://issuer.example:admins",
		Permission: "doctor.read",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	srv := New(Config{
		DBPath:        dbPath,
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
		AdminWarnDays: 0,
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/doctor/auth", nil)
	req.SetBasicAuth("admin", "admin-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"check":"authz_binding_unknown_issuer"`) {
		t.Fatalf("expected auth-only finding, got %s", body)
	}
	if strings.Contains(body, `"check":"public_active_count"`) {
		t.Fatalf("expected auth-only doctor payload, got %s", body)
	}
}

func TestAdminAuthIssuerListAndProbe(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAuthIssuer(storage.AuthIssuer{
		ID:           "issuer-1",
		Name:         "google-login",
		Enabled:      true,
		Issuer:       "https://accounts.google.com",
		Audiences:    []string{"uvoo-certctl"},
		DiscoveryURL: "http://127.0.0.1:1/.well-known/openid-configuration",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	srv := New(Config{
		DBPath:              dbPath,
		AdminUsername:       "admin",
		AdminPassword:       "admin-secret",
		ProviderHTTPTimeout: 50 * time.Millisecond,
	})

	listReq := httptest.NewRequest(http.MethodGet, "/admin/v1/auth-issuers", nil)
	listReq.SetBasicAuth("admin", "admin-secret")
	listRec := httptest.NewRecorder()
	srv.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRec.Code, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), `"google-login"`) {
		t.Fatalf("expected listed auth issuer, got %s", listRec.Body.String())
	}

	probeReq := httptest.NewRequest(http.MethodGet, "/admin/v1/auth-issuers/google-login?probe=true", nil)
	probeReq.SetBasicAuth("admin", "admin-secret")
	probeRec := httptest.NewRecorder()
	srv.ServeHTTP(probeRec, probeReq)
	if probeRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", probeRec.Code, probeRec.Body.String())
	}
	probeBody := probeRec.Body.String()
	if !strings.Contains(probeBody, `"connectivity_status":"error"`) {
		t.Fatalf("expected probed issuer status, got %s", probeBody)
	}
}

func TestAdminAuthProviderPresetsAndCreateIssuerFromPreset(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	srv := New(Config{
		DBPath:        dbPath,
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
	})

	listReq := httptest.NewRequest(http.MethodGet, "/admin/v1/auth-provider-presets", nil)
	listReq.SetBasicAuth("admin", "admin-secret")
	listRec := httptest.NewRecorder()
	srv.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRec.Code, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), `"name":"google"`) {
		t.Fatalf("expected preset list payload, got %s", listRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/v1/auth-provider-presets/keycloak", nil)
	getReq.SetBasicAuth("admin", "admin-secret")
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	if !strings.Contains(getRec.Body.String(), `"name":"keycloak"`) || !strings.Contains(getRec.Body.String(), `"requires_issuer":true`) {
		t.Fatalf("expected preset detail payload, got %s", getRec.Body.String())
	}

	createReq := httptest.NewRequest(http.MethodPost, "/admin/v1/auth-issuers", strings.NewReader(`{
		"preset":"keycloak",
		"name":"keycloak-dev",
		"issuer":"http://localhost:18080/realms/uvoo-certctl",
		"audiences":["uvoo-certctl"],
		"required_claims":{"azp":"uvoo-certctl"},
		"discovery_url":"http://keycloak:8080/realms/uvoo-certctl/.well-known/openid-configuration"
	}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.SetBasicAuth("admin", "admin-secret")
	createRec := httptest.NewRecorder()
	srv.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}
	body := createRec.Body.String()
	if !strings.Contains(body, `"name":"keycloak-dev"`) || !strings.Contains(body, `"roles_claims":["realm_access.roles"]`) {
		t.Fatalf("expected created issuer from preset, got %s", body)
	}
}

func TestAdminAuthIssuerCreateUpdateAndDelete(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	srv := New(Config{
		DBPath:        dbPath,
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
	})

	createReq := httptest.NewRequest(http.MethodPost, "/admin/v1/auth-issuers", strings.NewReader(`{
		"name":"keycloak-dev",
		"issuer":"http://localhost:18080/realms/uvoo-certctl",
		"audiences":["uvoo-certctl"],
		"required_claims":{"azp":"uvoo-certctl"},
		"discovery_url":"http://keycloak:8080/realms/uvoo-certctl/.well-known/openid-configuration",
		"roles_claims":["realm_access.roles"],
		"groups_claims":["groups"]
	}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.SetBasicAuth("admin", "admin-secret")
	createRec := httptest.NewRecorder()
	srv.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}
	if !strings.Contains(createRec.Body.String(), `"name":"keycloak-dev"`) {
		t.Fatalf("expected created auth issuer payload, got %s", createRec.Body.String())
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/admin/v1/auth-issuers/keycloak-dev", strings.NewReader(`{
		"name":"keycloak-local",
		"enabled":false,
		"jwks_url":"http://keycloak:8080/realms/uvoo-certctl/protocol/openid-connect/certs"
	}`))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.SetBasicAuth("admin", "admin-secret")
	updateRec := httptest.NewRecorder()
	srv.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateRec.Code, updateRec.Body.String())
	}
	updateBody := updateRec.Body.String()
	if !strings.Contains(updateBody, `"name":"keycloak-local"`) || !strings.Contains(updateBody, `"enabled":false`) {
		t.Fatalf("expected updated auth issuer payload, got %s", updateBody)
	}

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthzBinding(storage.AuthzBinding{
		ID:         "binding-issuer-1",
		Enabled:    true,
		Principal:  "role:http://localhost:18080/realms/uvoo-certctl:uvoo-certctl_admin",
		Permission: "doctor.read",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/v1/auth-issuers/keycloak-local", nil)
	deleteReq.SetBasicAuth("admin", "admin-secret")
	deleteRec := httptest.NewRecorder()
	srv.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}

	deleteForceReq := httptest.NewRequest(http.MethodDelete, "/admin/v1/auth-issuers/keycloak-local?force=true", nil)
	deleteForceReq.SetBasicAuth("admin", "admin-secret")
	deleteForceRec := httptest.NewRecorder()
	srv.ServeHTTP(deleteForceRec, deleteForceReq)
	if deleteForceRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", deleteForceRec.Code, deleteForceRec.Body.String())
	}
	if !strings.Contains(deleteForceRec.Body.String(), `"deleted":true`) || !strings.Contains(deleteForceRec.Body.String(), `"forced":true`) {
		t.Fatalf("expected forced delete payload, got %s", deleteForceRec.Body.String())
	}

	store, err = storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.GetAuthIssuerByIssuer("http://localhost:18080/realms/uvoo-certctl"); err == nil {
		t.Fatalf("expected auth issuer to be deleted")
	}
	if _, err := store.GetAuthzBindingByID("binding-issuer-1"); err == nil {
		t.Fatalf("expected referenced authz binding to be deleted")
	}
}

func TestAdminAuthzBindingListAndGet(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthzBinding(storage.AuthzBinding{
		ID:         "binding-1",
		Enabled:    true,
		Principal:  "role:https://sso.example.com/realms/uvoo-certctl:uvoo-certctl_admin",
		Permission: "doctor.read",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	srv := New(Config{
		DBPath:        dbPath,
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
	})

	listReq := httptest.NewRequest(http.MethodGet, "/admin/v1/authz-bindings?principal=role:https://sso.example.com/realms/uvoo-certctl:uvoo-certctl_admin", nil)
	listReq.SetBasicAuth("admin", "admin-secret")
	listRec := httptest.NewRecorder()
	srv.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRec.Code, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), `"binding-1"`) {
		t.Fatalf("expected listed authz binding, got %s", listRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/v1/authz-bindings/binding-1", nil)
	getReq.SetBasicAuth("admin", "admin-secret")
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	if !strings.Contains(getRec.Body.String(), `"permission":"doctor.read"`) {
		t.Fatalf("expected authz binding details, got %s", getRec.Body.String())
	}
}

func TestAdminAuthzBindingCreateUpdateAndDelete(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	srv := New(Config{
		DBPath:        dbPath,
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
	})

	createReq := httptest.NewRequest(http.MethodPost, "/admin/v1/authz-bindings", strings.NewReader(`{
		"principal":"role:https://sso.example.com/realms/uvoo-certctl:uvoo-certctl_admin",
		"permission":"doctor.read",
		"resource_kind":"subject",
		"resource_ref":"*"
	}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.SetBasicAuth("admin", "admin-secret")
	createRec := httptest.NewRecorder()
	srv.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}

	var created struct {
		ID         string `json:"id"`
		Principal  string `json:"principal"`
		Permission string `json:"permission"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Permission != "doctor.read" {
		t.Fatalf("unexpected create payload: %+v", created)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/admin/v1/authz-bindings/"+created.ID, strings.NewReader(`{
		"permission":"metrics.read",
		"enabled":false
	}`))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.SetBasicAuth("admin", "admin-secret")
	updateRec := httptest.NewRecorder()
	srv.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateRec.Code, updateRec.Body.String())
	}
	updateBody := updateRec.Body.String()
	if !strings.Contains(updateBody, `"permission":"metrics.read"`) || !strings.Contains(updateBody, `"enabled":false`) {
		t.Fatalf("expected updated authz binding payload, got %s", updateBody)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/v1/authz-bindings/"+created.ID, nil)
	deleteReq.SetBasicAuth("admin", "admin-secret")
	deleteRec := httptest.NewRecorder()
	srv.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
	if !strings.Contains(deleteRec.Body.String(), `"deleted":true`) {
		t.Fatalf("expected deleted payload, got %s", deleteRec.Body.String())
	}

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.GetAuthzBindingByID(created.ID); err == nil {
		t.Fatalf("expected authz binding to be deleted")
	}
}

func TestAdminCSRSubmitListAndRejectFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	srv := New(Config{
		DBPath:        dbPath,
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
		AdminWarnDays: 30,
	})

	submitReq := httptest.NewRequest(http.MethodPost, "/admin/v1/csr-requests", strings.NewReader(`{
		"kind":"private",
		"csr_pem":`+quoteJSON(t, string(mustCreateServerTestCSR(t, "api.internal", []string{"api.internal"})))+`,
		"requester_name":"Jane Doe",
		"requester_email":"jane@example.com",
		"organization":"Uvoo",
		"department":"Platform"
	}`))
	submitReq.Header.Set("Content-Type", "application/json")
	submitReq.SetBasicAuth("admin", "admin-secret")
	submitRec := httptest.NewRecorder()
	srv.ServeHTTP(submitRec, submitReq)
	if submitRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", submitRec.Code, submitRec.Body.String())
	}

	var submitResp struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(submitRec.Body.Bytes(), &submitResp); err != nil {
		t.Fatal(err)
	}
	if submitResp.ID == "" || submitResp.Status != storage.CSRStatusPending {
		t.Fatalf("unexpected submit response: %+v", submitResp)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/v1/csr-requests", nil)
	listReq.SetBasicAuth("admin", "admin-secret")
	listRec := httptest.NewRecorder()
	srv.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRec.Code, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), submitResp.ID) {
		t.Fatalf("expected list response to contain request id, got %s", listRec.Body.String())
	}

	rejectReq := httptest.NewRequest(http.MethodPost, "/admin/v1/csr-requests/"+submitResp.ID+"/reject", strings.NewReader(`{"reason":"unable to verify requester"}`))
	rejectReq.Header.Set("Content-Type", "application/json")
	rejectReq.SetBasicAuth("admin", "admin-secret")
	rejectRec := httptest.NewRecorder()
	srv.ServeHTTP(rejectRec, rejectReq)
	if rejectRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rejectRec.Code, rejectRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/v1/csr-requests/"+submitResp.ID, nil)
	getReq.SetBasicAuth("admin", "admin-secret")
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	body := getRec.Body.String()
	if !strings.Contains(body, `"status":"rejected"`) || !strings.Contains(body, `"decision_note":"unable to verify requester"`) {
		t.Fatalf("expected rejected response, got %s", body)
	}
}

func TestAdminApprovePrivateCSRFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	rootPassword := "Root-secret-please-changeA1"
	icaPassword := "Ica-secret-please-changeA1"

	rootCA, err := ops.CreatePrivateRootCA(store, ops.CreatePrivateRootCAParams{
		Name:           "corp-root",
		CommonName:     "Corp Root CA",
		Days:           3650,
		KeyType:        "ec256",
		CryptoPassword: rootPassword,
		Org:            "Uvoo",
		OrgUnit:        "Platform",
		Country:        "US",
	})
	if err != nil {
		t.Fatal(err)
	}

	ica, err := ops.CreatePrivateIntermediateCA(store, ops.CreatePrivateIntermediateCAParams{
		RootID:              rootCA.ID,
		Name:                "corp-issuing",
		CommonName:          "Corp Issuing CA",
		Days:                1825,
		KeyType:             "ec256",
		IssuerPassword:      rootPassword,
		ChildCryptoPassword: icaPassword,
		Org:                 "Uvoo",
		OrgUnit:             "Platform",
		Country:             "US",
	})
	if err != nil {
		t.Fatal(err)
	}

	submitResult, err := ops.SubmitCSR(store, ops.SubmitCSRParams{
		Kind:            storage.CertKindPrivate,
		CSRData:         mustCreateServerTestCSR(t, "api.internal", []string{"api.internal", "api2.internal"}),
		RequesterName:   "Jane Doe",
		RequesterEmail:  "jane@example.com",
		Organization:    "Uvoo",
		Department:      "Platform",
		RequestedCAName: ica.Name,
		CertType:        "server",
		RequestedDays:   365,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	srv := New(Config{
		DBPath:                  dbPath,
		AdminUsername:           "admin",
		AdminPassword:           "admin-secret",
		AdminWarnDays:           30,
		DefaultIntermediateName: ica.Name,
	})

	approveBody := map[string]any{
		"intermediate_name":   ica.Name,
		"parent_key_password": icaPassword,
		"decision_note":       "approved",
	}
	bodyBytes, err := json.Marshal(approveBody)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/csr-requests/"+submitResult.Request.ID+"/approve", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "admin-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"issued"`) || !strings.Contains(rec.Body.String(), `"private_key_stored":false`) {
		t.Fatalf("expected issued private cert response, got %s", rec.Body.String())
	}

	store, err = storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	csrReq, err := store.GetCSRRequestByID(submitResult.Request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if csrReq.Status != storage.CSRStatusIssued || csrReq.IssuedCertID == "" {
		t.Fatalf("unexpected csr request state: %+v", csrReq)
	}
	if _, err := store.GetPrivateCertByID(csrReq.IssuedCertID); err != nil {
		t.Fatalf("expected issued private cert to exist: %v", err)
	}
}

func TestAdminSubjectListApproveAndUpdateFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertSubjectSeen(storage.Subject{
		ID:       "subject-1",
		Issuer:   "https://accounts.google.com",
		Subject:  "user-123",
		Status:   storage.SubjectStatusPending,
		Username: "alice",
		Email:    "alice@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	srv := New(Config{
		DBPath:        dbPath,
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
	})

	listReq := httptest.NewRequest(http.MethodGet, "/admin/v1/subjects?status=pending", nil)
	listReq.SetBasicAuth("admin", "admin-secret")
	listRec := httptest.NewRecorder()
	srv.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRec.Code, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), `"user-123"`) {
		t.Fatalf("expected listed subject, got %s", listRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/v1/subjects/subject-1", nil)
	getReq.SetBasicAuth("admin", "admin-secret")
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	if !strings.Contains(getRec.Body.String(), `"id":"subject-1"`) {
		t.Fatalf("expected subject item response, got %s", getRec.Body.String())
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/admin/v1/subjects/approve", strings.NewReader(`{
		"issuer":"https://accounts.google.com",
		"subject":"user-123",
		"local_groups":["viewers"]
	}`))
	approveReq.Header.Set("Content-Type", "application/json")
	approveReq.SetBasicAuth("admin", "admin-secret")
	approveRec := httptest.NewRecorder()
	srv.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", approveRec.Code, approveRec.Body.String())
	}
	if !strings.Contains(approveRec.Body.String(), `"status":"active"`) || !strings.Contains(approveRec.Body.String(), `"local_groups":["viewers"]`) {
		t.Fatalf("expected approved subject response, got %s", approveRec.Body.String())
	}

	updateReq := httptest.NewRequest(http.MethodPost, "/admin/v1/subjects/update", strings.NewReader(`{
		"issuer":"https://accounts.google.com",
		"subject":"user-123",
		"status":"disabled",
		"local_roles":["auditor"]
	}`))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.SetBasicAuth("admin", "admin-secret")
	updateRec := httptest.NewRecorder()
	srv.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateRec.Code, updateRec.Body.String())
	}
	body := updateRec.Body.String()
	if !strings.Contains(body, `"status":"disabled"`) || !strings.Contains(body, `"local_roles":["auditor"]`) {
		t.Fatalf("expected updated subject response, got %s", body)
	}

	updateByIDReq := httptest.NewRequest(http.MethodPut, "/admin/v1/subjects/subject-1", strings.NewReader(`{
		"status":"active",
		"local_groups":["employees"]
	}`))
	updateByIDReq.Header.Set("Content-Type", "application/json")
	updateByIDReq.SetBasicAuth("admin", "admin-secret")
	updateByIDRec := httptest.NewRecorder()
	srv.ServeHTTP(updateByIDRec, updateByIDReq)
	if updateByIDRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateByIDRec.Code, updateByIDRec.Body.String())
	}
	updateByIDBody := updateByIDRec.Body.String()
	if !strings.Contains(updateByIDBody, `"status":"active"`) || !strings.Contains(updateByIDBody, `"local_groups":["employees"]`) {
		t.Fatalf("expected updated subject by id response, got %s", updateByIDBody)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/v1/subjects/subject-1", nil)
	deleteReq.SetBasicAuth("admin", "admin-secret")
	deleteRec := httptest.NewRecorder()
	srv.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
	if !strings.Contains(deleteRec.Body.String(), `"deleted":true`) {
		t.Fatalf("expected deleted subject response, got %s", deleteRec.Body.String())
	}
}

func TestAdminSubjectAutoApprovalCRUDFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	srv := New(Config{
		DBPath:        dbPath,
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
	})

	putReq := httptest.NewRequest(http.MethodPut, "/admin/v1/subject-auto-approvals/google-employees", strings.NewReader(`{
		"issuer":"https://accounts.google.com",
		"email_domain":"example.com",
		"required_groups":["employees"],
		"local_groups":["employees"],
		"enabled":true
	}`))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.SetBasicAuth("admin", "admin-secret")
	putRec := httptest.NewRecorder()
	srv.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", putRec.Code, putRec.Body.String())
	}
	if !strings.Contains(putRec.Body.String(), `"name":"google-employees"`) {
		t.Fatalf("expected upserted rule, got %s", putRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/v1/subject-auto-approvals", nil)
	listReq.SetBasicAuth("admin", "admin-secret")
	listRec := httptest.NewRecorder()
	srv.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRec.Code, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), `"google-employees"`) {
		t.Fatalf("expected rule in list response, got %s", listRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/v1/subject-auto-approvals/google-employees", nil)
	getReq.SetBasicAuth("admin", "admin-secret")
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	if !strings.Contains(getRec.Body.String(), `"email_domain":"example.com"`) {
		t.Fatalf("expected rule details, got %s", getRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/v1/subject-auto-approvals/google-employees", nil)
	deleteReq.SetBasicAuth("admin", "admin-secret")
	deleteRec := httptest.NewRecorder()
	srv.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
	if !strings.Contains(deleteRec.Body.String(), `"deleted":true`) {
		t.Fatalf("expected deleted response, got %s", deleteRec.Body.String())
	}
}

func TestMetricsEndpointRequiresAuthWhenAdminEnabled(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ops.SubmitCSR(store, ops.SubmitCSRParams{
		Kind:          storage.CertKindPrivate,
		CSRData:       mustCreateServerTestCSR(t, "metrics.internal", []string{"metrics.internal"}),
		RequesterName: "Jane Doe",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAuthIssuer(storage.AuthIssuer{
		ID:        "issuer-1",
		Name:      "google-login",
		Enabled:   true,
		Issuer:    "https://accounts.google.com",
		Audiences: []string{"uvoo-certctl"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAuthIssuer(storage.AuthIssuer{
		ID:        "issuer-2",
		Name:      "keycloak-dev",
		Enabled:   true,
		Issuer:    "https://sso.example.com/realms/uvoo-certctl",
		Audiences: []string{"uvoo-certctl"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAuthIssuer(storage.AuthIssuer{
		ID:        "issuer-3",
		Name:      "disabled-issuer",
		Enabled:   false,
		Issuer:    "https://disabled.example.com/realms/uvoo-certctl",
		Audiences: []string{"uvoo-certctl"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthzBinding(storage.AuthzBinding{
		ID:         "binding-1",
		Enabled:    true,
		Principal:  "role:https://sso.example.com/realms/uvoo-certctl:uvoo-certctl_admin",
		Permission: "doctor.read",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthzBinding(storage.AuthzBinding{
		ID:         "binding-2",
		Enabled:    true,
		Principal:  "role:https://unknown.example.com/realms/uvoo-certctl:unknown_admin",
		Permission: "metrics.read",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthzBinding(storage.AuthzBinding{
		ID:          "binding-3",
		Enabled:     true,
		Principal:   "role:https://disabled.example.com/realms/uvoo-certctl:legacy_admin",
		Permission:  "subject.update",
		ResourceRef: "*",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthzBinding(storage.AuthzBinding{
		ID:         "binding-4",
		Enabled:    true,
		Principal:  "superuser",
		Permission: "*",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertSubjectAutoApprovalRule(storage.SubjectAutoApprovalRule{
		ID:      "rule-1",
		Name:    "broad-google",
		Enabled: true,
		Issuer:  "https://accounts.google.com",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertSubjectAutoApprovalRule(storage.SubjectAutoApprovalRule{
		ID:      "rule-2",
		Name:    "unknown-issuer-rule",
		Enabled: true,
		Issuer:  "https://missing.example.com/realms/uvoo-certctl",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	srv := New(Config{
		DBPath:        dbPath,
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
		AdminWarnDays: 30,
		EnableMetrics: true,
	})
	srv.recordIssuerProbe("https://accounts.google.com", nil)
	srv.recordIssuerProbe("https://sso.example.com/realms/uvoo-certctl", assertErr("probe failed"))

	unauthReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	unauthRec := httptest.NewRecorder()
	srv.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", unauthRec.Code, unauthRec.Body.String())
	}

	authReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	authReq.SetBasicAuth("admin", "admin-secret")
	authRec := httptest.NewRecorder()
	srv.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", authRec.Code, authRec.Body.String())
	}
	body := authRec.Body.String()
	if !strings.Contains(body, "uvoo-certctl_csr_requests_total") ||
		!strings.Contains(body, "uvoo-certctl_pending_csr_requests_older_than_days_total") ||
		!strings.Contains(body, "uvoo-certctl_pending_csr_requests_total") ||
		!strings.Contains(body, "uvoo-certctl_csr_requests_ready_for_pickup_total") ||
		!strings.Contains(body, "uvoo-certctl_auth_issuers_total") ||
		!strings.Contains(body, "uvoo-certctl_auth_issuers_connectivity_status_total") ||
		!strings.Contains(body, "uvoo-certctl_auth_issuer_binding_coverage_total") ||
		!strings.Contains(body, "uvoo-certctl_authz_bindings_total") ||
		!strings.Contains(body, "uvoo-certctl_authz_bindings_by_permission_total") ||
		!strings.Contains(body, "uvoo-certctl_authz_bindings_by_principal_kind_total") ||
		!strings.Contains(body, "uvoo-certctl_authz_bindings_risky_total") ||
		!strings.Contains(body, "uvoo-certctl_doctor_findings_total") ||
		!strings.Contains(body, "uvoo-certctl_auth_requests_total") ||
		!strings.Contains(body, "uvoo-certctl_subject_auto_approval_rules_total") ||
		!strings.Contains(body, "uvoo-certctl_subject_auto_approval_rules_risky_total") ||
		!strings.Contains(body, "uvoo-certctl_subject_auto_approval_matches_total") ||
		!strings.Contains(body, "uvoo-certctl_pending_subjects_total") ||
		!strings.Contains(body, "uvoo-certctl_pending_subjects_older_than_days_total") ||
		!strings.Contains(body, "uvoo-certctl_subjects_total") {
		t.Fatalf("expected metrics output, got %s", body)
	}
	if !strings.Contains(body, `state="enabled_without_bindings"`) ||
		!strings.Contains(body, `status="ok"`) ||
		!strings.Contains(body, `status="error"`) ||
		!strings.Contains(body, `status="disabled"`) ||
		!strings.Contains(body, `state="disabled_referenced"`) ||
		!strings.Contains(body, `state="unknown_referenced"`) ||
		!strings.Contains(body, `check="auth_issuer_discovery"`) ||
		!strings.Contains(body, `principal_kind="superuser"`) ||
		!strings.Contains(body, `risk="wildcard_permission"`) ||
		!strings.Contains(body, `risk="broad"`) ||
		!strings.Contains(body, `risk="unknown_issuer"`) {
		t.Fatalf("expected auth summary labels in metrics output, got %s", body)
	}
}

func TestMetricsEndpointAllowsDedicatedMetricsBasicAuth(t *testing.T) {
	srv := New(Config{
		DBPath:          filepath.Join(t.TempDir(), "certs.db"),
		AdminUsername:   "admin",
		AdminPassword:   "admin-secret",
		MetricsUsername: "metrics",
		MetricsPassword: "metrics-secret",
		AdminWarnDays:   30,
		EnableMetrics:   true,
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.SetBasicAuth("metrics", "metrics-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `uvoo-certctl_auth_requests_total{`) ||
		!strings.Contains(body, `auth_method="basic_metrics"`) ||
		!strings.Contains(body, `result="allowed"`) {
		t.Fatalf("expected metrics auth counter for dedicated metrics basic auth, got %s", body)
	}
}

func quoteJSON(t *testing.T, v string) string {
	t.Helper()
	buf, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf)
}

func assertErr(msg string) error {
	return &testError{msg: msg}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
