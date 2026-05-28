package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"certctl/internal/dns"
	"certctl/internal/ops"
	"certctl/internal/storage"
	"certctl/internal/util"
)

type providerFlags struct {
	Provider    string
	APIUser     string
	APIKey      string
	ClientIP    string
	DNSResolver string
}

func (f providerFlags) config() dns.Config {
	return dns.Config{
		Provider:    f.Provider,
		APIUser:     f.APIUser,
		APIKey:      f.APIKey,
		ClientIP:    f.ClientIP,
		HTTPTimeout: rootCfg.HTTPTimeout,
	}
}

func (f providerFlags) validate() error {
	if err := util.Require("provider", f.Provider); err != nil {
		return err
	}
	if err := util.Require("api-user", f.APIUser); err != nil {
		return err
	}
	if err := util.Require("api-key", f.APIKey); err != nil {
		return err
	}
	if strings.EqualFold(f.Provider, "namecheap") {
		if err := util.Require("client-ip for namecheap", f.ClientIP); err != nil {
			return err
		}
	}
	return nil
}

func providerFromFlags(ctx context.Context, f providerFlags) (dns.Provider, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	p, err := dns.NewProvider(f.config())
	if err != nil {
		return nil, err
	}
	_ = ctx
	return p, nil
}

func withTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), timeout)
}

func printKV(label, value string) {
	fmt.Printf("%-18s %s\n", label+":", value)
}

func warnPublicSANConflicts(store *storage.Store, commonName string, sans []string) error {
	conflicts, err := ops.ListPublicSANConflicts(store, commonName, sans)
	if err != nil {
		return err
	}
	printSANConflicts(conflicts)
	return nil
}

func warnPrivateSANConflicts(store *storage.Store, commonName string, sans []string) error {
	conflicts, err := ops.ListPrivateSANConflicts(store, commonName, sans)
	if err != nil {
		return err
	}
	printSANConflicts(conflicts)
	return nil
}

func printSANConflicts(conflicts []ops.SANConflict) {
	if len(conflicts) == 0 {
		return
	}
	for _, conflict := range conflicts {
		fmt.Printf("[warn] active SAN overlap with %s: %s\n", conflict.CommonName, strings.Join(conflict.SANs, ", "))
	}
}

func logAuditEvent(store *storage.Store, action, targetKind, targetID, summary string) {
	if store == nil {
		return
	}
	_ = store.LogAuditEvent(storage.AuditEvent{
		ID:         util.NewID(),
		Action:     action,
		TargetKind: targetKind,
		TargetID:   targetID,
		Summary:    summary,
	})
}
