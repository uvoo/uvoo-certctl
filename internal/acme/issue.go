package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	legoNamecheap "github.com/go-acme/lego/v4/providers/dns/namecheap"
	"github.com/go-acme/lego/v4/registration"
)

type user struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *user) GetEmail() string                        { return u.Email }
func (u *user) GetRegistration() *registration.Resource { return u.Registration }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

type IssueOptions struct {
	Email       string
	Domains     []string
	Provider    string
	APIUser     string
	APIKey      string
	ClientIP    string
	Timeout     time.Duration
	UseStaging  bool
	Propagation time.Duration
	KeyType     string
}

type IssueForCSROptions struct {
	Email       string
	CSR         *x509.CertificateRequest
	Provider    string
	APIUser     string
	APIKey      string
	ClientIP    string
	Timeout     time.Duration
	UseStaging  bool
	Propagation time.Duration
}

func Issue(ctx context.Context, opts IssueOptions) (*certificate.Resource, error) {
	if len(opts.Domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	u := &user{
		Email: opts.Email,
		key:   privateKey,
	}

	config := lego.NewConfig(u)
	if opts.UseStaging {
		config.CADirURL = lego.LEDirectoryStaging
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}

	switch strings.ToLower(strings.TrimSpace(opts.KeyType)) {
	case "", "ec256":
		config.Certificate.KeyType = certcrypto.EC256
	case "ec384":
		config.Certificate.KeyType = certcrypto.EC384
	case "rsa2048":
		config.Certificate.KeyType = certcrypto.RSA2048
	case "rsa4096":
		config.Certificate.KeyType = certcrypto.RSA4096
	default:
		return nil, fmt.Errorf("unsupported key type: %s (supported: ec256, ec384, rsa2048, rsa4096)", opts.KeyType)
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	if err := configureDNSProvider(client, opts); err != nil {
		return nil, err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return nil, err
	}
	u.Registration = reg

	request := certificate.ObtainRequest{
		Domains: opts.Domains,
		Bundle:  true,
	}

	_ = ctx

	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

func IssueForCSR(ctx context.Context, opts IssueForCSROptions) (*certificate.Resource, error) {
	if opts.CSR == nil {
		return nil, fmt.Errorf("csr is required")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	u := &user{
		Email: opts.Email,
		key:   privateKey,
	}

	config := lego.NewConfig(u)
	if opts.UseStaging {
		config.CADirURL = lego.LEDirectoryStaging
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	if err := configureDNSProvider(client, IssueOptions{
		Provider:    opts.Provider,
		APIUser:     opts.APIUser,
		APIKey:      opts.APIKey,
		ClientIP:    opts.ClientIP,
		Timeout:     opts.Timeout,
		Propagation: opts.Propagation,
	}); err != nil {
		return nil, err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return nil, err
	}
	u.Registration = reg

	request := certificate.ObtainForCSRRequest{
		CSR:    opts.CSR,
		Bundle: true,
	}

	_ = ctx

	return client.Certificate.ObtainForCSR(request)
}

func configureDNSProvider(client *lego.Client, opts IssueOptions) error {
	switch strings.ToLower(strings.TrimSpace(opts.Provider)) {
	case "godaddy":
		_ = os.Setenv("GODADDY_API_KEY", opts.APIUser)
		_ = os.Setenv("GODADDY_API_SECRET", opts.APIKey)

		p, err := godaddy.NewDNSProvider()
		if err != nil {
			return err
		}
		return client.Challenge.SetDNS01Provider(p)

	case "namecheap":
		config := legoNamecheap.NewDefaultConfig()
		config.APIUser = opts.APIUser
		config.APIKey = opts.APIKey
		config.ClientIP = opts.ClientIP

		if opts.Propagation > 0 {
			config.PropagationTimeout = opts.Propagation
		}
		if opts.Timeout > 0 {
			config.HTTPClient.Timeout = opts.Timeout
		}

		p, err := legoNamecheap.NewDNSProviderConfig(config)
		if err != nil {
			return err
		}
		return client.Challenge.SetDNS01Provider(p)

	default:
		return fmt.Errorf("unsupported provider: %s", opts.Provider)
	}
}
