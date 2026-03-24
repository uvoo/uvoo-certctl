package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func (u *user) GetEmail() string { return u.Email }
func (u *user) GetRegistration() *registration.Resource { return u.Registration }
func (u *user) GetPrivateKey() crypto.PrivateKey { return u.key }

type IssueOptions struct {
	Email       string
	Domain      string
	Provider    string
	APIUser     string
	APIKey      string
	ClientIP    string
	Timeout     time.Duration
	UseStaging  bool
	Propagation time.Duration
}

func Issue(ctx context.Context, opts IssueOptions) (*certificate.Resource, error) {
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
	config.Certificate.KeyType = certcrypto.RSA2048

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
		Domains: []string{opts.Domain},
		Bundle:  true,
	}

	_ = ctx // currently unused by lego directly

	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}

	return certs, nil
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
