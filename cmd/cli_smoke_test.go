package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"uvoo-certctl/internal/storage"
)

func TestBackupRestoreAndDoctorCommands(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(storage.PublicCert{
		ID:         "pub-1",
		CommonName: "api.example.com",
		SANsCSV:    "api.example.com",
		SANsHash:   "hash-1",
		CertPEM:    []byte("cert-1"),
		KeyPEM:     []byte("key-1"),
		NotBefore:  time.Now().UTC().Add(-time.Hour),
		NotAfter:   time.Now().UTC().Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(t.TempDir(), "backup.db")
	out, err := runRootCommandForTest("--db", dbPath, "backup-db", "--out", backupPath, "--json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"backup"`) {
		t.Fatalf("expected backup JSON output, got %s", out)
	}

	store, err = storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(storage.PublicCert{
		ID:         "pub-2",
		CommonName: "api2.example.com",
		SANsCSV:    "api2.example.com",
		SANsHash:   "hash-2",
		CertPEM:    []byte("cert-2"),
		KeyPEM:     []byte("key-2"),
		NotBefore:  time.Now().UTC().Add(-time.Hour),
		NotAfter:   time.Now().UTC().Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	out, err = runRootCommandForTest("--db", dbPath, "restore-db", "--from", backupPath, "--force", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"restored_from"`) {
		t.Fatalf("expected restore JSON output, got %s", out)
	}

	store, err = storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	rows, err := store.List("", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].CommonName != "api.example.com" {
		t.Fatalf("expected restored DB to contain original cert only, got %+v", rows)
	}

	out, err = runRootCommandForTest("--db", dbPath, "doctor", "--warn-days", "0", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"status": "ok"`) {
		t.Fatalf("expected doctor ok JSON output, got %s", out)
	}
}

func TestVersionCommandJSON(t *testing.T) {
	out, err := runRootCommandForTest("version", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"version"`) || !strings.Contains(out, `"commit"`) {
		t.Fatalf("expected version JSON output, got %s", out)
	}
}

func TestAuthCommandsJSON(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth.db")
	issuerURL := "https://issuer.example.test/realms/uvoo-certctl"

	out, err := runRootCommandForTest(
		"--db", dbPath,
		"create-auth-issuer",
		"--name", "keycloak-local",
		"--issuer", issuerURL,
		"--audience", "uvoo-certctl",
		"--required-claim", "azp=uvoo-certctl-cli",
		"--json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"required_claims"`) {
		t.Fatalf("expected required_claims in issuer output, got %s", out)
	}

	out, err = runRootCommandForTest(
		"--db", dbPath,
		"create-authz-binding",
		"--principal", "role:"+issuerURL+":uvoo-certctl_admin",
		"--permission", "doctor.read",
		"--json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"doctor.read"`) {
		t.Fatalf("expected authz binding output, got %s", out)
	}

	out, err = runRootCommandForTest(
		"--db", dbPath,
		"list-effective-authz",
		"--principal", "role:"+issuerURL+":uvoo-certctl_admin",
		"--json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"effective_permissions"`) || !strings.Contains(out, `"doctor.read"`) {
		t.Fatalf("expected effective authz output, got %s", out)
	}

	out, err = runRootCommandForTest(
		"--db", dbPath,
		"update-authz-binding",
		"--match-principal", "role:"+issuerURL+":uvoo-certctl_admin",
		"--match-permission", "doctor.read",
		"--permission", "metrics.read",
		"--json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"metrics.read"`) {
		t.Fatalf("expected updated authz binding output, got %s", out)
	}

	out, err = runRootCommandForTest(
		"--db", dbPath,
		"create-subject-auto-approval",
		"--name", "issuer-admins",
		"--issuer", issuerURL,
		"--email-domain", "example.com",
		"--local-group", "employees",
		"--json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"email_domain": "example.com"`) {
		t.Fatalf("expected subject auto approval output, got %s", out)
	}

	out, err = runRootCommandForTest(
		"--db", dbPath,
		"list-subject-auto-approvals",
		"--json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"issuer-admins"`) {
		t.Fatalf("expected listed subject auto approval, got %s", out)
	}

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertSubjectSeen(storage.Subject{
		ID:       "subject-1",
		Issuer:   issuerURL,
		Subject:  "user-1",
		Status:   storage.SubjectStatusPending,
		Username: "alice",
		Email:    "alice@example.com",
	}); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	out, err = runRootCommandForTest(
		"--db", dbPath,
		"update-subject",
		"--issuer", issuerURL,
		"--subject", "user-1",
		"--status", "active",
		"--local-role", "admin",
		"--local-group", "ops",
		"--json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"status": "active"`) || !strings.Contains(out, `"local_roles"`) {
		t.Fatalf("expected updated subject output, got %s", out)
	}
}

func runRootCommandForTest(args ...string) (string, error) {
	oldCfg := rootCfg
	defer func() {
		rootCfg = oldCfg
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs(args)

	err := rootCmd.Execute()
	output := stdout.String() + stderr.String()

	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	rootCmd.SetArgs(nil)

	return output, err
}
