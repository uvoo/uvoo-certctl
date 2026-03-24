package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"certctl/internal/util"
)

type Record struct {
	Name string
	Type string
	TTL  int
	Data string
}

type Provider interface {
	Name() string
	CheckCredentials(ctx context.Context) error
	CheckZoneAccess(ctx context.Context, domain string) error
	ListRecords(ctx context.Context, domain string) ([]Record, error)
	CreateRecord(ctx context.Context, domain, name, typ, value string, ttl int) error
	DeleteRecord(ctx context.Context, domain, name, typ, value string) error
}

type Config struct {
	Provider    string
	APIUser     string
	APIKey      string
	ClientIP    string
	HTTPTimeout time.Duration
}

func NewProvider(cfg Config) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "godaddy":
		return NewGoDaddyProvider(cfg)
	case "namecheap":
		return NewNamecheapProvider(cfg)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", cfg.Provider)
	}
}

func EnsureResolvable(ctx context.Context, fqdn, resolver string) error {
	fqdn = util.BaseLookupDomain(fqdn)
	var r *net.Resolver
	if strings.TrimSpace(resolver) == "" {
		r = net.DefaultResolver
	} else {
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, net.JoinHostPort(resolver, "53"))
			},
		}
	}
	_, err := r.LookupHost(ctx, fqdn)
	return err
}

func CheckPrecursors(ctx context.Context, p Provider, domain, resolver string, writeTest bool) error {
	if err := p.CheckCredentials(ctx); err != nil {
		return fmt.Errorf("provider credentials check failed: %w", err)
	}
	if err := p.CheckZoneAccess(ctx, domain); err != nil {
		return fmt.Errorf("zone access check failed: %w", err)
	}
	if err := EnsureResolvable(ctx, domain, resolver); err != nil {
		return fmt.Errorf("public DNS lookup failed: %w", err)
	}
	if writeTest {
		zone, err := util.RootZone(domain)
		if err != nil {
			return err
		}
		name := util.RelativeRecordName(zone, "_certctl-preflight-"+fmt.Sprintf("%d", time.Now().Unix())+"."+zone)
		value := fmt.Sprintf("certctl-preflight-%d", time.Now().UnixNano())
		if err := p.CreateRecord(ctx, zone, name, "TXT", value, 60); err != nil {
			return fmt.Errorf("temporary write test create failed: %w", err)
		}
		defer func() { _ = p.DeleteRecord(context.Background(), zone, name, "TXT", value) }()
	}
	return nil
}
