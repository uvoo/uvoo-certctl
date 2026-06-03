package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"uvoo-certctl/internal/cli"
	"uvoo-certctl/internal/privateca"
	"uvoo-certctl/internal/storage"
)

func TestApprovePrivateCSRRequestEndToEnd(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	rootRes, rootKey, rootCert, err := privateca.CreateRootCA(privateca.CreateRootOptions{
		CommonName: "Corp Root",
		KeyType:    "ec256",
		Days:       3650,
	})
	if err != nil {
		t.Fatal(err)
	}
	rootKeyPEM, err := marshalPrivateKeyPEMForTest(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	encRootKey, err := cli.Encrypt(rootKeyPEM, "RootPassword!1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPrivateRootCA(storage.PrivateRootCA{
		ID:         "root-1",
		Name:       "corp-root",
		CommonName: "Corp Root",
		KeyType:    "ec256",
		CertPEM:    rootRes.CertPEM,
		KeyPEM:     encRootKey,
		Issuer:     rootRes.Issuer,
		NotBefore:  rootRes.NotBefore,
		NotAfter:   rootRes.NotAfter,
		Status:     storage.StatusActive,
		IsTrusted:  true,
		IsIssuing:  true,
	}); err != nil {
		t.Fatal(err)
	}

	icaRes, icaKey, _, err := privateca.CreateIntermediateCA(rootCert, rootKey, privateca.CreateIntermediateOptions{
		CommonName: "Corp Issuing",
		KeyType:    "ec256",
		Days:       1825,
	})
	if err != nil {
		t.Fatal(err)
	}
	icaKeyPEM, err := marshalPrivateKeyPEMForTest(icaKey)
	if err != nil {
		t.Fatal(err)
	}
	encICAKey, err := cli.Encrypt(icaKeyPEM, "IcaPassword!1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPrivateIntermediateCA(storage.PrivateIntermediateCA{
		ID:         "ica-1",
		RootCAID:   "root-1",
		Name:       "corp-issuing",
		CommonName: "Corp Issuing",
		KeyType:    "ec256",
		CertPEM:    icaRes.CertPEM,
		KeyPEM:     encICAKey,
		Issuer:     icaRes.Issuer,
		NotBefore:  icaRes.NotBefore,
		NotAfter:   icaRes.NotAfter,
		Status:     storage.StatusActive,
		IsTrusted:  true,
		IsIssuing:  true,
	}); err != nil {
		t.Fatal(err)
	}

	req := storage.CSRRequest{
		ID:              "csr-1",
		Kind:            storage.CertKindPrivate,
		CSRPEM:          mustCreateCSRForCmdTest(t, "api.internal", []string{"api.internal"}, nil, nil),
		CommonName:      "api.internal",
		SANsCSV:         "api.internal",
		PickupTokenHash: "hash",
		RequestedCAName: "corp-issuing",
		CertType:        "server",
	}
	if err := store.CreateCSRRequest(req); err != nil {
		t.Fatal(err)
	}

	rec, err := approvePrivateCSRRequest(store, req, approvePrivateCSRConfig{
		IntermediateName: "corp-issuing",
		ParentPassword:   "IcaPassword!1",
		CertType:         "server",
		Days:             365,
		DecisionNote:     "approved",
	})
	if err != nil {
		t.Fatal(err)
	}
	if privateKeyStored(rec.KeyPEM) {
		t.Fatal("expected csr-backed private cert to omit stored private key")
	}

	updatedReq, err := store.GetCSRRequestByID("csr-1")
	if err != nil {
		t.Fatal(err)
	}
	if updatedReq.Status != storage.CSRStatusIssued || updatedReq.IssuedCertID == "" {
		t.Fatalf("expected issued csr request, got %+v", updatedReq)
	}
}

func TestValidatePublicCSRRejectsIPAndEmailOnly(t *testing.T) {
	ipCSR, _, err := privateca.ParseCertificateRequest(mustCreateCSRForCmdTest(t, "", nil, []string{"192.0.2.10"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePublicCSR(ipCSR); err == nil {
		t.Fatal("expected IP-only CSR to be rejected")
	}

	emailCSR, _, err := privateca.ParseCertificateRequest(mustCreateCSRForCmdTest(t, "", nil, nil, []string{"user@example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePublicCSR(emailCSR); err == nil {
		t.Fatal("expected email-only CSR to be rejected")
	}
}

func TestCSRBackedPrivateCertBlocksKeyExportAndShareKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "certs.db")
	seedCSRBackedPrivateCert(t, dbPath)

	out, err := runRootCommandForTest("--db", dbPath, "export-private-cert", "--common-name", "api.internal")
	if err == nil || !strings.Contains(err.Error(), "private key is not stored for csr-based private certificate") {
		t.Fatalf("expected export-private-cert to fail cleanly, err=%v output=%s", err, out)
	}

	out, err = runRootCommandForTest("--db", dbPath, "share-cert", "--kind", "private", "--name", "api.internal", "--mode", "cert_key", "--share-password", "share-pass", "--key-password", "key-pass")
	if err == nil || !strings.Contains(err.Error(), "private key is not stored for csr-based private certificate") {
		t.Fatalf("expected share-cert cert_key to fail cleanly, err=%v output=%s", err, out)
	}
}

func seedCSRBackedPrivateCert(t *testing.T, dbPath string) {
	t.Helper()

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.UpsertPrivateRootCA(storage.PrivateRootCA{
		ID:         "root-1",
		Name:       "corp-root",
		CommonName: "Corp Root",
		KeyType:    "ec256",
		CertPEM:    []byte("root-cert"),
		KeyPEM:     []byte("root-key"),
		Status:     storage.StatusActive,
		IsTrusted:  true,
		IsIssuing:  true,
		NotBefore:  time.Now().UTC().Add(-time.Hour),
		NotAfter:   time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPrivateIntermediateCA(storage.PrivateIntermediateCA{
		ID:         "ica-1",
		RootCAID:   "root-1",
		Name:       "corp-issuing",
		CommonName: "Corp Issuing",
		KeyType:    "ec256",
		CertPEM:    []byte("ica-cert"),
		KeyPEM:     []byte("ica-key"),
		Status:     storage.StatusActive,
		IsTrusted:  true,
		IsIssuing:  true,
		NotBefore:  time.Now().UTC().Add(-time.Hour),
		NotAfter:   time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPrivateCert(storage.PrivateCert{
		ID:               "leaf-1",
		IntermediateCAID: "ica-1",
		CommonName:       "api.internal",
		SANsCSV:          "api.internal",
		CertType:         "server",
		KeyType:          "ec256",
		CertPEM:          []byte("leaf-cert"),
		KeyPEM:           nil,
		Status:           storage.StatusActive,
		NotBefore:        time.Now().UTC().Add(-time.Hour),
		NotAfter:         time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
}

func mustCreateCSRForCmdTest(t *testing.T, commonName string, dnsNames, ipStrings, emails []string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var ips []net.IP
	for _, s := range ipStrings {
		ips = append(ips, net.ParseIP(s))
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: commonName},
		DNSNames:       dnsNames,
		IPAddresses:    ips,
		EmailAddresses: emails,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func marshalPrivateKeyPEMForTest(key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
