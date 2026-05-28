package privateca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

type IssueLeafFromCSROptions struct {
	CertType string
	Days     int
}

func ParseCertificateRequest(data []byte) (*x509.CertificateRequest, []byte, error) {
	data = bytesTrimSpace(data)
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("empty csr data")
	}

	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, nil, fmt.Errorf("unsupported csr pem block type: %s", block.Type)
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return csr, pem.EncodeToMemory(block), nil
	}

	csr, err := x509.ParseCertificateRequest(data)
	if err != nil {
		return nil, nil, err
	}
	return csr, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: data}), nil
}

func CSRIdentity(csr *x509.CertificateRequest) (commonName string, sans []string) {
	if csr == nil {
		return "", nil
	}

	commonName = strings.TrimSpace(csr.Subject.CommonName)
	if commonName == "" {
		switch {
		case len(csr.DNSNames) > 0:
			commonName = csr.DNSNames[0]
		case len(csr.IPAddresses) > 0:
			commonName = csr.IPAddresses[0].String()
		case len(csr.EmailAddresses) > 0:
			commonName = csr.EmailAddresses[0]
		case len(csr.URIs) > 0 && csr.URIs[0] != nil:
			commonName = csr.URIs[0].String()
		}
	}

	set := map[string]struct{}{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := set[v]; ok {
			return
		}
		set[v] = struct{}{}
		sans = append(sans, v)
	}

	for _, v := range csr.DNSNames {
		add(v)
	}
	for _, v := range csr.IPAddresses {
		add(v.String())
	}
	for _, v := range csr.EmailAddresses {
		add(v)
	}
	for _, v := range csr.URIs {
		if v != nil {
			add(v.String())
		}
	}

	return commonName, sans
}

func CSRPrimaryDNSOrIP(csr *x509.CertificateRequest) string {
	if csr == nil {
		return ""
	}
	if commonName, _ := CSRIdentity(csr); commonName != "" {
		return commonName
	}
	return ""
}

func CSRFingerprintSHA256(csrPEM []byte) string {
	sum := sha256.Sum256(csrPEM)
	return hex.EncodeToString(sum[:])
}

func PublicKeyType(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return string(KeyTypeEC256)
		case elliptic.P384():
			return string(KeyTypeEC384)
		default:
			return "ecdsa"
		}
	case *rsa.PublicKey:
		switch k.Size() * 8 {
		case 2048:
			return string(KeyTypeRSA2048)
		case 4096:
			return string(KeyTypeRSA4096)
		default:
			return fmt.Sprintf("rsa%d", k.Size()*8)
		}
	case ed25519.PublicKey:
		return string(KeyTypeED25519)
	default:
		return "external"
	}
}

func IssueLeafFromCSR(parentCert *x509.Certificate, parentKey crypto.PrivateKey, csr *x509.CertificateRequest, opts IssueLeafFromCSROptions) (*Result, error) {
	if parentCert == nil || parentKey == nil {
		return nil, fmt.Errorf("parent certificate and key are required")
	}
	if csr == nil {
		return nil, fmt.Errorf("csr is required")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid csr signature: %w", err)
	}

	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.Add(time.Duration(opts.Days) * 24 * time.Hour)

	serial, err := randSerial()
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          subjectKeyID(csr.PublicKey),
		AuthorityKeyId:        parentCert.SubjectKeyId,
		DNSNames:              slices.Clone(csr.DNSNames),
		EmailAddresses:        slices.Clone(csr.EmailAddresses),
		IPAddresses:           cloneIPs(csr.IPAddresses),
		URIs:                  cloneURIs(csr.URIs),
	}

	switch strings.ToLower(strings.TrimSpace(opts.CertType)) {
	case "", "server":
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "server_client":
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return nil, fmt.Errorf("unsupported cert type: %s", opts.CertType)
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, parentCert, csr.PublicKey, parentKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &Result{
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.UTC(),
		NotAfter:  cert.NotAfter.UTC(),
	}, nil
}

func cloneIPs(values []net.IP) []net.IP {
	if len(values) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(values))
	for _, v := range values {
		out = append(out, append(net.IP(nil), v...))
	}
	return out
}

func cloneURIs(values []*url.URL) []*url.URL {
	if len(values) == 0 {
		return nil
	}
	out := make([]*url.URL, 0, len(values))
	for _, v := range values {
		if v == nil {
			continue
		}
		copyValue := *v
		out = append(out, &copyValue)
	}
	return out
}

func bytesTrimSpace(data []byte) []byte {
	return []byte(strings.TrimSpace(string(data)))
}
