package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"
)

func TestPublicCertRotationSupersedesPrevious(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	rec1 := PublicCert{
		ID:         "pub-1",
		CommonName: "api.example.com",
		SANsCSV:    "api.example.com",
		SANsHash:   "hash-1",
		CertPEM:    []byte("cert-1"),
		KeyPEM:     []byte("key-1"),
		NotBefore:  time.Now().UTC().Add(-time.Hour),
		NotAfter:   time.Now().UTC().Add(24 * time.Hour),
	}
	rec2 := PublicCert{
		ID:         "pub-2",
		CommonName: "api.example.com",
		SANsCSV:    "api.example.com,www.example.com",
		SANsHash:   "hash-2",
		CertPEM:    []byte("cert-2"),
		KeyPEM:     []byte("key-2"),
		NotBefore:  time.Now().UTC().Add(-time.Hour),
		NotAfter:   time.Now().UTC().Add(48 * time.Hour),
	}

	if err := store.Upsert(rec1); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(rec2); err != nil {
		t.Fatal(err)
	}

	active, err := store.GetByCommonName("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if active.ID != "pub-2" {
		t.Fatalf("expected newest cert active, got %s", active.ID)
	}

	history, err := store.ListPublicCertHistory("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 history rows, got %d", len(history))
	}
	if history[0].Status != StatusActive {
		t.Fatalf("expected newest row active, got %s", history[0].Status)
	}
	if history[1].Status != StatusSuperseded {
		t.Fatalf("expected older row superseded, got %s", history[1].Status)
	}
}

func TestPromotePrivateRootCARetiresCurrentActive(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	root1 := PrivateRootCA{
		ID:         "root-1",
		Name:       "corp-root",
		CommonName: "Corp Root",
		KeyType:    "ec256",
		CertPEM:    []byte("cert-1"),
		KeyPEM:     []byte("key-1"),
		NotBefore:  time.Now().UTC().Add(-time.Hour),
		NotAfter:   time.Now().UTC().Add(24 * time.Hour),
		Status:     StatusActive,
		IsTrusted:  true,
		IsIssuing:  true,
	}
	root2 := PrivateRootCA{
		ID:         "root-2",
		Name:       "corp-root",
		CommonName: "Corp Root",
		KeyType:    "ec256",
		CertPEM:    []byte("cert-2"),
		KeyPEM:     []byte("key-2"),
		NotBefore:  time.Now().UTC().Add(-time.Hour),
		NotAfter:   time.Now().UTC().Add(48 * time.Hour),
		Status:     StatusActive,
		IsTrusted:  true,
		IsIssuing:  true,
	}

	if err := store.UpsertPrivateRootCA(root1); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPrivateRootCA(root2); err != nil {
		t.Fatal(err)
	}
	if err := store.PromotePrivateRootCA("root-1"); err != nil {
		t.Fatal(err)
	}

	rows, err := store.ListPrivateRootCAs("corp-root", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 root rows, got %d", len(rows))
	}

	var activeCount int
	var promoted PrivateRootCA
	for _, row := range rows {
		if row.Status == StatusActive {
			activeCount++
			promoted = row
		}
	}
	if activeCount != 1 {
		t.Fatalf("expected exactly one active root, got %d", activeCount)
	}
	if promoted.ID != "root-1" {
		t.Fatalf("expected root-1 to be promoted, got %s", promoted.ID)
	}
}

func TestLegacyPrivateCertMigrationBuildsHistory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}

	stmts := []string{
		`CREATE TABLE private_root_cas (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			common_name TEXT NOT NULL,
			key_type TEXT NOT NULL,
			cert_pem BLOB NOT NULL,
			key_pem BLOB NOT NULL,
			issuer TEXT,
			not_before TEXT,
			not_after TEXT,
			created_at TEXT,
			updated_at TEXT
		)`,
		`CREATE TABLE private_intermediate_cas (
			id TEXT PRIMARY KEY,
			root_ca_id TEXT NOT NULL,
			name TEXT NOT NULL UNIQUE,
			common_name TEXT NOT NULL,
			key_type TEXT NOT NULL,
			cert_pem BLOB NOT NULL,
			key_pem BLOB NOT NULL,
			issuer TEXT,
			not_before TEXT,
			not_after TEXT,
			created_at TEXT,
			updated_at TEXT
		)`,
		`CREATE TABLE private_certs (
			id TEXT PRIMARY KEY,
			intermediate_ca_id TEXT NOT NULL,
			common_name TEXT NOT NULL,
			sans_csv TEXT,
			cert_type TEXT NOT NULL,
			key_type TEXT NOT NULL,
			cert_pem BLOB NOT NULL,
			key_pem BLOB NOT NULL,
			issuer TEXT,
			not_before TEXT,
			not_after TEXT,
			created_at TEXT,
			updated_at TEXT
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := db.Exec(`
		INSERT INTO private_root_cas (id, name, common_name, key_type, cert_pem, key_pem, created_at, updated_at)
		VALUES ('root-1', 'corp-root', 'Corp Root', 'ec256', X'01', X'02', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO private_intermediate_cas (id, root_ca_id, name, common_name, key_type, cert_pem, key_pem, created_at, updated_at)
		VALUES ('ica-1', 'root-1', 'corp-ica', 'Corp ICA', 'ec256', X'03', X'04', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO private_certs (id, intermediate_ca_id, common_name, sans_csv, cert_type, key_type, cert_pem, key_pem, created_at, updated_at)
		VALUES
		('leaf-1', 'ica-1', 'api.internal', 'api.internal', 'server', 'ec256', X'05', X'06', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
		('leaf-2', 'ica-1', 'api.internal', 'api.internal,api2.internal', 'server', 'ec256', X'07', X'08', '2026-02-01T00:00:00Z', '2026-02-01T00:00:00Z')
	`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	history, err := store.ListPrivateCertHistory("api.internal")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 rows after migration, got %d", len(history))
	}
	if history[0].ID != "leaf-2" || history[0].Status != StatusActive {
		t.Fatalf("expected newest migrated row active, got %s %s", history[0].ID, history[0].Status)
	}
	if history[1].Status != StatusSuperseded {
		t.Fatalf("expected older migrated row superseded, got %s", history[1].Status)
	}
}

func TestAuditEventRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.LogAuditEvent(AuditEvent{
		ID:         "audit-1",
		Action:     "test_action",
		TargetKind: "database",
		TargetID:   dbPath,
		Summary:    "hello",
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := store.ListAuditEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(rows))
	}
	if rows[0].Action != "test_action" || rows[0].Summary != "hello" {
		t.Fatalf("unexpected audit row: %+v", rows[0])
	}
}

func TestSetAuthIssuerEnabled(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.UpsertAuthIssuer(AuthIssuer{
		ID:           "issuer-1",
		Name:         "keycloak-local",
		Enabled:      true,
		Issuer:       "https://issuer.example.test/realms/uvoo-certctl",
		Audiences:    []string{"uvoo-certctl"},
		RolesClaims:  []string{"realm_access.roles"},
		GroupsClaims: []string{"groups"},
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.SetAuthIssuerEnabled("https://issuer.example.test/realms/uvoo-certctl", false); err != nil {
		t.Fatal(err)
	}

	rec, err := store.GetAuthIssuerByIssuer("https://issuer.example.test/realms/uvoo-certctl")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Enabled {
		t.Fatal("expected issuer to be disabled")
	}
}

func TestDeleteAuthIssuerRemovesRecord(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth-delete.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.UpsertAuthIssuer(AuthIssuer{
		ID:        "issuer-1",
		Name:      "keycloak-local",
		Enabled:   true,
		Issuer:    "https://issuer.example.test/realms/uvoo-certctl",
		Audiences: []string{"uvoo-certctl"},
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteAuthIssuer("https://issuer.example.test/realms/uvoo-certctl"); err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetAuthIssuerByIssuer("https://issuer.example.test/realms/uvoo-certctl"); err == nil {
		t.Fatal("expected deleted issuer lookup to fail")
	}
}

func TestAuthIssuerRoundTripRequiredClaims(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth-required-claims.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.UpsertAuthIssuer(AuthIssuer{
		ID:             "issuer-1",
		Name:           "keycloak-local",
		Enabled:        true,
		Issuer:         "https://issuer.example.test/realms/uvoo-certctl",
		Audiences:      []string{"uvoo-certctl"},
		RequiredClaims: map[string]string{"azp": "uvoo-certctl-cli", "tid": "tenant-1"},
	}); err != nil {
		t.Fatal(err)
	}

	rec, err := store.GetAuthIssuerByIssuer("https://issuer.example.test/realms/uvoo-certctl")
	if err != nil {
		t.Fatal(err)
	}
	if rec.RequiredClaims["azp"] != "uvoo-certctl-cli" || rec.RequiredClaims["tid"] != "tenant-1" {
		t.Fatalf("unexpected required claims: %+v", rec.RequiredClaims)
	}
}

func TestSubjectAutoApprovalRuleRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "subject-auto-approval.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.UpsertSubjectAutoApprovalRule(SubjectAutoApprovalRule{
		ID:             "rule-1",
		Name:           "google-employees",
		Enabled:        true,
		Issuer:         "https://accounts.google.com",
		EmailDomain:    "@example.com",
		RequiredRoles:  []string{"employee"},
		RequiredGroups: []string{"engineering"},
		LocalRoles:     []string{"viewer"},
		LocalGroups:    []string{"employees"},
	}); err != nil {
		t.Fatal(err)
	}

	rec, err := store.GetSubjectAutoApprovalRuleByName("google-employees")
	if err != nil {
		t.Fatal(err)
	}
	if rec.EmailDomain != "example.com" {
		t.Fatalf("expected normalized email domain, got %q", rec.EmailDomain)
	}
	if len(rec.RequiredRoles) != 1 || rec.RequiredRoles[0] != "employee" {
		t.Fatalf("unexpected required roles: %+v", rec.RequiredRoles)
	}

	rows, err := store.ListSubjectAutoApprovalRules(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Name != "google-employees" {
		t.Fatalf("unexpected rules: %+v", rows)
	}

	if err := store.DeleteSubjectAutoApprovalRule("google-employees"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSubjectAutoApprovalRuleByName("google-employees"); err == nil {
		t.Fatal("expected deleted subject auto approval rule lookup to fail")
	}
}

func TestUpdateAuthzBindingPersistsChanges(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "authz-update.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.CreateAuthzBinding(AuthzBinding{
		ID:         "binding-1",
		Enabled:    true,
		Principal:  "role:https://issuer.example.test/realms/uvoo-certctl:uvoo-certctl_admin",
		Permission: "doctor.read",
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.UpdateAuthzBinding(AuthzBinding{
		ID:           "binding-1",
		Enabled:      false,
		Principal:    "role:https://issuer.example.test/realms/uvoo-certctl:uvoo-certctl_ops",
		Permission:   "csr.approve",
		ResourceKind: "csr_request",
		ResourceRef:  "*",
	}); err != nil {
		t.Fatal(err)
	}

	rec, err := store.GetAuthzBindingByID("binding-1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Enabled {
		t.Fatal("expected binding to be disabled")
	}
	if rec.Permission != "csr.approve" || rec.ResourceKind != "csr_request" || rec.ResourceRef != "*" {
		t.Fatalf("unexpected updated binding: %+v", rec)
	}
}

func TestDeleteAuthzBindingRemovesRecord(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "authz-delete.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.CreateAuthzBinding(AuthzBinding{
		ID:         "binding-1",
		Enabled:    true,
		Principal:  "role:https://issuer.example.test/realms/uvoo-certctl:uvoo-certctl_admin",
		Permission: "doctor.read",
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteAuthzBinding("binding-1"); err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetAuthzBindingByID("binding-1"); err == nil {
		t.Fatal("expected deleted binding lookup to fail")
	}
}

func TestCSRRequestLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "csr.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	req := CSRRequest{
		ID:                "csr-1",
		Kind:              CertKindPrivate,
		CSRPEM:            mustCreateTestCSR(t, "api.internal", []string{"api.internal"}),
		FingerprintSHA256: "fingerprint-1",
		CommonName:        "api.internal",
		SANsCSV:           "api.internal",
		RequesterName:     "Jane Doe",
		PickupTokenHash:   "hash-1",
	}
	if err := store.CreateCSRRequest(req); err != nil {
		t.Fatal(err)
	}

	rows, err := store.ListCSRRequests("", CSRStatusPending)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 pending csr request, got %d", len(rows))
	}
	if rows[0].Status != CSRStatusPending {
		t.Fatalf("expected pending status, got %s", rows[0].Status)
	}

	if err := store.MarkCSRRequestIssued("csr-1", "leaf-1", "approved"); err != nil {
		t.Fatal(err)
	}
	issued, err := store.GetCSRRequestByID("csr-1")
	if err != nil {
		t.Fatal(err)
	}
	if issued.Status != CSRStatusIssued || issued.IssuedCertID != "leaf-1" {
		t.Fatalf("expected issued csr request, got %+v", issued)
	}

	req2 := CSRRequest{
		ID:              "csr-2",
		Kind:            CertKindPublic,
		CSRPEM:          mustCreateTestCSR(t, "api.example.com", []string{"api.example.com"}),
		CommonName:      "api.example.com",
		SANsCSV:         "api.example.com",
		PickupTokenHash: "hash-2",
	}
	if err := store.CreateCSRRequest(req2); err != nil {
		t.Fatal(err)
	}
	if err := store.RejectCSRRequest("csr-2", "verification failed"); err != nil {
		t.Fatal(err)
	}
	rejected, err := store.GetCSRRequestByID("csr-2")
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Status != CSRStatusRejected {
		t.Fatalf("expected rejected status, got %s", rejected.Status)
	}
}

func mustCreateTestCSR(t *testing.T, commonName string, dnsNames []string) []byte {
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
