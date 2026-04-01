package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"certctl/internal/ops"
	"certctl/internal/storage"
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
	if !strings.Contains(body, "certctl_csr_requests_total") ||
		!strings.Contains(body, "certctl_pending_csr_requests_older_than_days_total") ||
		!strings.Contains(body, "certctl_pending_csr_requests_total") ||
		!strings.Contains(body, "certctl_csr_requests_ready_for_pickup_total") ||
		!strings.Contains(body, "certctl_auth_issuers_total") ||
		!strings.Contains(body, "certctl_authz_bindings_total") ||
		!strings.Contains(body, "certctl_auth_requests_total") ||
		!strings.Contains(body, "certctl_subject_auto_approval_rules_total") ||
		!strings.Contains(body, "certctl_subject_auto_approval_matches_total") ||
		!strings.Contains(body, "certctl_pending_subjects_total") ||
		!strings.Contains(body, "certctl_pending_subjects_older_than_days_total") ||
		!strings.Contains(body, "certctl_subjects_total") {
		t.Fatalf("expected metrics output, got %s", body)
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
	if !strings.Contains(body, `certctl_auth_requests_total{`) ||
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
