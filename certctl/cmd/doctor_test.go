package cmd

import (
	"testing"
	"time"

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
	})
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
	})
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

type fakeDoctorStore struct {
	publicRows  []storage.PublicCert
	privateRows []storage.PrivateCert
	rootRows    []storage.PrivateRootCA
	icaRows     []storage.PrivateIntermediateCA
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

var _ doctorStore = (*fakeDoctorStore)(nil)
