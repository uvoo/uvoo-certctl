package privateca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

type KeyType string

const (
	KeyTypeEC256   KeyType = "ec256"
	KeyTypeEC384   KeyType = "ec384"
	KeyTypeRSA2048 KeyType = "rsa2048"
	KeyTypeRSA4096 KeyType = "rsa4096"
	KeyTypeED25519 KeyType = "ed25519"
)

type CreateRootOptions struct {
	CommonName string
	KeyType    string
	Days       int
	Org        string
	OrgUnit    string
	Country    string
	Province   string
	Locality   string
}

type CreateIntermediateOptions struct {
	CommonName string
	KeyType    string
	Days       int
	Org        string
	OrgUnit    string
	Country    string
	Province   string
	Locality   string
}

type IssueLeafOptions struct {
	CommonName string
	Domains    []string
	CertType   string
	KeyType    string
	Days       int
	Org        string
	OrgUnit    string
	Country    string
	Province   string
	Locality   string
}

type Result struct {
	CertPEM   []byte
	KeyPEM    []byte
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
}

func CreateRootCA(opts CreateRootOptions) (*Result, crypto.PrivateKey, *x509.Certificate, error) {
	priv, signer, pub, err := generateKey(opts.KeyType)
	if err != nil {
		return nil, nil, nil, err
	}

	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.Add(time.Duration(opts.Days) * 24 * time.Hour)

	serial, err := randSerial()
	if err != nil {
		return nil, nil, nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         opts.CommonName,
			Organization:       nonEmptySlice(opts.Org),
			OrganizationalUnit: nonEmptySlice(opts.OrgUnit),
			Country:            nonEmptySlice(opts.Country),
			Province:           nonEmptySlice(opts.Province),
			Locality:           nonEmptySlice(opts.Locality),
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		SubjectKeyId:          subjectKeyID(pub),
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, signer)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err := marshalPrivateKeyPEM(priv)
	if err != nil {
		return nil, nil, nil, err
	}

	return &Result{
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.UTC(),
		NotAfter:  cert.NotAfter.UTC(),
	}, priv, cert, nil
}

func CreateIntermediateCA(parentCert *x509.Certificate, parentKey crypto.PrivateKey, opts CreateIntermediateOptions) (*Result, crypto.PrivateKey, *x509.Certificate, error) {
	priv, _, pub, err := generateKey(opts.KeyType)
	if err != nil {
		return nil, nil, nil, err
	}

	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.Add(time.Duration(opts.Days) * 24 * time.Hour)

	serial, err := randSerial()
	if err != nil {
		return nil, nil, nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         opts.CommonName,
			Organization:       nonEmptySlice(opts.Org),
			OrganizationalUnit: nonEmptySlice(opts.OrgUnit),
			Country:            nonEmptySlice(opts.Country),
			Province:           nonEmptySlice(opts.Province),
			Locality:           nonEmptySlice(opts.Locality),
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          subjectKeyID(pub),
		AuthorityKeyId:        parentCert.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, parentCert, pub, parentKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err := marshalPrivateKeyPEM(priv)
	if err != nil {
		return nil, nil, nil, err
	}

	return &Result{
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.UTC(),
		NotAfter:  cert.NotAfter.UTC(),
	}, priv, cert, nil
}

func IssueLeaf(parentCert *x509.Certificate, parentKey crypto.PrivateKey, opts IssueLeafOptions) (*Result, crypto.PrivateKey, error) {
	priv, _, pub, err := generateKey(opts.KeyType)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.Add(time.Duration(opts.Days) * 24 * time.Hour)

	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         opts.CommonName,
			Organization:       nonEmptySlice(opts.Org),
			OrganizationalUnit: nonEmptySlice(opts.OrgUnit),
			Country:            nonEmptySlice(opts.Country),
			Province:           nonEmptySlice(opts.Province),
			Locality:           nonEmptySlice(opts.Locality),
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          subjectKeyID(pub),
		AuthorityKeyId:        parentCert.SubjectKeyId,
	}

	var dnsNames []string
	for _, d := range opts.Domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if ip := net.ParseIP(d); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			dnsNames = append(dnsNames, d)
		}
	}
	tpl.DNSNames = dnsNames

	switch strings.ToLower(strings.TrimSpace(opts.CertType)) {
	case "", "server":
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "server_client":
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return nil, nil, fmt.Errorf("unsupported cert type: %s", opts.CertType)
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, parentCert, pub, parentKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err := marshalPrivateKeyPEM(priv)
	if err != nil {
		return nil, nil, err
	}

	return &Result{
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.UTC(),
		NotAfter:  cert.NotAfter.UTC(),
	}, priv, nil
}

func ParseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func ParsePrivateKeyPEM(keyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}

	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key PEM")
}

func generateKey(keyType string) (crypto.PrivateKey, crypto.PrivateKey, crypto.PublicKey, error) {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "", "ec256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		return k, k, k.Public(), nil
	case "ec384":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		return k, k, k.Public(), nil
	case "rsa2048":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, nil, err
		}
		return k, k, k.Public(), nil
	case "rsa4096":
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, nil, err
		}
		return k, k, k.Public(), nil
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		return priv, priv, pub, nil
	default:
		return nil, nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

func marshalPrivateKeyPEM(priv crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func subjectKeyID(pub crypto.PublicKey) []byte {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha1Sum(spki)
	return sum[:]
}

func sha1Sum(b []byte) [20]byte {
	// local wrapper to keep imports tidy in one file if desired
	return sha1Array(b)
}

func nonEmptySlice(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return []string{v}
}
