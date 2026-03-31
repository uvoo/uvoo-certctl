package cmd

import (
	"testing"
	"time"

	"certctl/internal/ops"
	"certctl/internal/storage"
)

func TestRunDoctorReportsMissingIntermediateReference(t *testing.T) {
	now := time.Now().UTC()
	findings, err := runDoctor(&fakeDoctorStore{
		publicRows: []storage.PublicCert{},
		privateRows: []storage.PrivateCert{
			{
				ID:               "leaf-1",
				CommonName:       "api.internal",
				IntermediateCAID: "missing-ica",
				Status:           storage.StatusActive,
				NotAfter:         now.Add(time.Hour),
			},
		},
		rootRows: []storage.PrivateRootCA{},
		icaRows:  []storage.PrivateIntermediateCA{},
	}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	found := false
	for _, finding := range findings {
		if finding.Check == "private_issuer_ref" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected private_issuer_ref finding, got %+v", findings)
	}
}

func TestRunDoctorReportsMultipleActiveRoots(t *testing.T) {
	findings, err := runDoctor(&fakeDoctorStore{
		rootRows: []storage.PrivateRootCA{
			{ID: "root-1", Name: "corp-root", Status: storage.StatusActive, IsIssuing: true, NotAfter: time.Now().UTC().Add(time.Hour)},
			{ID: "root-2", Name: "corp-root", Status: storage.StatusActive, IsIssuing: true, NotAfter: time.Now().UTC().Add(time.Hour)},
		},
	}, 30)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range findings {
		if finding.Check == "root_active_count" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected root_active_count finding, got %+v", findings)
	}
}

func TestRunDoctorWarnsOnUpcomingExpiryAndStaleItems(t *testing.T) {
	now := time.Now().UTC()
	findings, err := runDoctor(&fakeDoctorStore{
		publicRows: []storage.PublicCert{
			{ID: "pub-1", CommonName: "www.example.com", Status: storage.StatusActive, NotAfter: now.Add(48 * time.Hour)},
		},
		privateRows: []storage.PrivateCert{
			{ID: "priv-1", CommonName: "api.internal", Status: storage.StatusActive, NotAfter: now.Add(72 * time.Hour), IntermediateCAID: "ica-1"},
		},
		rootRows: []storage.PrivateRootCA{
			{ID: "root-1", Name: "corp-root", Status: storage.StatusActive, NotAfter: now.Add(96 * time.Hour)},
		},
		icaRows: []storage.PrivateIntermediateCA{
			{ID: "ica-1", RootCAID: "root-1", Name: "corp-issuing", CommonName: "Corp Issuing", Status: storage.StatusActive, NotAfter: now.Add(120 * time.Hour)},
		},
		shares: []storage.CertShare{
			{ID: "share-1", CertID: "priv-1", ExpiresAt: now.Add(24 * time.Hour)},
		},
		csrRows: []storage.CSRRequest{
			{ID: "csr-1", Kind: storage.CertKindPrivate, Status: storage.CSRStatusPending, CommonName: "api.internal", CreatedAt: now.Add(-8 * 24 * time.Hour)},
		},
	}, 7)
	if err != nil {
		t.Fatal(err)
	}

	wantChecks := map[string]bool{
		"public_expiring":       false,
		"private_expiring":      false,
		"root_expiring":         false,
		"intermediate_expiring": false,
		"share_expiring":        false,
		"csr_pending_age":       false,
	}
	for _, finding := range findings {
		if _, ok := wantChecks[finding.Check]; ok {
			wantChecks[finding.Check] = true
		}
	}
	for check, found := range wantChecks {
		if !found {
			t.Fatalf("expected %s finding, got %+v", check, findings)
		}
	}
}

func TestRunDoctorWarnsOnExpiredShare(t *testing.T) {
	now := time.Now().UTC()
	findings, err := runDoctor(&fakeDoctorStore{
		shares: []storage.CertShare{
			{ID: "share-1", CertID: "pub-1", ExpiresAt: now.Add(-time.Hour)},
		},
	}, 30)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, finding := range findings {
		if finding.Check == "share_expired" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected share_expired finding, got %+v", findings)
	}
}

func TestRunDoctorWarnDaysZeroDisablesTimeWarnings(t *testing.T) {
	now := time.Now().UTC()
	findings, err := runDoctor(&fakeDoctorStore{
		publicRows: []storage.PublicCert{
			{ID: "pub-1", CommonName: "www.example.com", Status: storage.StatusActive, NotAfter: now.Add(24 * time.Hour)},
		},
		shares: []storage.CertShare{
			{ID: "share-1", CertID: "pub-1", ExpiresAt: now.Add(-time.Hour)},
		},
		csrRows: []storage.CSRRequest{
			{ID: "csr-1", Kind: storage.CertKindPublic, Status: storage.CSRStatusPending, CommonName: "www.example.com", CreatedAt: now.Add(-30 * 24 * time.Hour)},
		},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no time-based findings when warn-days is disabled, got %+v", findings)
	}
}

func TestRunDoctorWarnsOnDisabledIssuerStillReferenced(t *testing.T) {
	findings, err := runDoctorWithOptions(&fakeDoctorStore{
		authIssuers: []storage.AuthIssuer{
			{
				ID:      "issuer-1",
				Name:    "keycloak-local",
				Issuer:  "https://issuer.example.test/realms/certctl",
				Enabled: false,
			},
		},
		authzBindings: []storage.AuthzBinding{
			{
				ID:         "binding-1",
				Enabled:    true,
				Principal:  "role:https://issuer.example.test/realms/certctl:certctl_admin",
				Permission: "doctor.read",
			},
		},
	}, ops.DoctorOptions{WarnDays: 0})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, finding := range findings {
		if finding.Check == "auth_issuer_disabled_reference" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected auth_issuer_disabled_reference finding, got %+v", findings)
	}
}

func TestRunDoctorWarnsOnBrokenIssuerDiscovery(t *testing.T) {
	findings, err := runDoctorWithOptions(&fakeDoctorStore{
		authIssuers: []storage.AuthIssuer{
			{
				ID:      "issuer-1",
				Name:    "keycloak-local",
				Issuer:  "https://issuer.example.test/realms/certctl",
				Enabled: true,
			},
		},
	}, ops.DoctorOptions{
		WarnDays: 0,
		AuthIssuerProbe: func(issuer storage.AuthIssuer) error {
			if issuer.Issuer == "https://issuer.example.test/realms/certctl" {
				return assertErr("oidc discovery failed with status 500")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, finding := range findings {
		if finding.Check == "auth_issuer_discovery" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected auth_issuer_discovery finding, got %+v", findings)
	}
}

func TestRunDoctorWarnsOnBindingReferencingUnknownIssuer(t *testing.T) {
	findings, err := runDoctorWithOptions(&fakeDoctorStore{
		authIssuers: []storage.AuthIssuer{
			{
				ID:      "issuer-1",
				Name:    "keycloak-local",
				Issuer:  "https://issuer.example.test/realms/certctl",
				Enabled: true,
			},
		},
		authzBindings: []storage.AuthzBinding{
			{
				ID:         "binding-1",
				Enabled:    true,
				Principal:  "role:https://missing-issuer.example.test/realms/certctl:certctl_admin",
				Permission: "doctor.read",
			},
		},
	}, ops.DoctorOptions{WarnDays: 0})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, finding := range findings {
		if finding.Check == "authz_binding_unknown_issuer" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected authz_binding_unknown_issuer finding, got %+v", findings)
	}
}

type fakeDoctorStore struct {
	publicRows    []storage.PublicCert
	privateRows   []storage.PrivateCert
	rootRows      []storage.PrivateRootCA
	icaRows       []storage.PrivateIntermediateCA
	shares        []storage.CertShare
	csrRows       []storage.CSRRequest
	authIssuers   []storage.AuthIssuer
	authzBindings []storage.AuthzBinding
}

func (f *fakeDoctorStore) List(_ string, _ bool) ([]storage.PublicCert, error) {
	return f.publicRows, nil
}

func (f *fakeDoctorStore) ListPrivateCerts(_ string, _ bool) ([]storage.PrivateCert, error) {
	return f.privateRows, nil
}

func (f *fakeDoctorStore) ListPrivateRootCAs(_ string, _ bool) ([]storage.PrivateRootCA, error) {
	return f.rootRows, nil
}

func (f *fakeDoctorStore) ListPrivateIntermediateCAs(_ string, _ bool) ([]storage.PrivateIntermediateCA, error) {
	return f.icaRows, nil
}

func (f *fakeDoctorStore) ListShares(_ string) ([]storage.CertShare, error) {
	return f.shares, nil
}

func (f *fakeDoctorStore) ListCSRRequests(_, _ string) ([]storage.CSRRequest, error) {
	return f.csrRows, nil
}

func (f *fakeDoctorStore) ListAuthIssuers(_ bool) ([]storage.AuthIssuer, error) {
	return f.authIssuers, nil
}

func (f *fakeDoctorStore) ListAuthzBindings(_ bool) ([]storage.AuthzBinding, error) {
	return f.authzBindings, nil
}

var _ doctorStore = (*fakeDoctorStore)(nil)

type assertErr string

func (e assertErr) Error() string { return string(e) }
