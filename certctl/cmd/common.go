package cmd

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"certctl/internal/dns"
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
	rows, err := store.List("", false)
	if err != nil {
		return err
	}
	conflicts := collectSANConflicts(commonName, sans, func() []sanRecord {
		out := make([]sanRecord, 0, len(rows))
		for _, row := range rows {
			out = append(out, sanRecord{
				ID:         row.ID,
				CommonName: row.CommonName,
				SANsCSV:    row.SANsCSV,
				Status:     row.Status,
			})
		}
		return out
	}())
	printSANConflicts(conflicts)
	return nil
}

func warnPrivateSANConflicts(store *storage.Store, commonName string, sans []string) error {
	rows, err := store.ListPrivateCerts("", false)
	if err != nil {
		return err
	}
	conflicts := collectSANConflicts(commonName, sans, func() []sanRecord {
		out := make([]sanRecord, 0, len(rows))
		for _, row := range rows {
			out = append(out, sanRecord{
				ID:         row.ID,
				CommonName: row.CommonName,
				SANsCSV:    row.SANsCSV,
				Status:     row.Status,
			})
		}
		return out
	}())
	printSANConflicts(conflicts)
	return nil
}

type sanRecord struct {
	ID         string
	CommonName string
	SANsCSV    string
	Status     string
}

func collectSANConflicts(commonName string, sans []string, rows []sanRecord) map[string][]string {
	targetSet := map[string]struct{}{}
	for _, name := range sans {
		for _, normalized := range splitCSVNames(name) {
			targetSet[normalized] = struct{}{}
		}
	}

	conflicts := map[string][]string{}
	for _, row := range rows {
		if row.CommonName == commonName || row.Status != storage.StatusActive {
			continue
		}
		for _, candidate := range splitCSVNames(row.SANsCSV) {
			if _, ok := targetSet[candidate]; ok {
				conflicts[row.CommonName] = append(conflicts[row.CommonName], candidate)
			}
		}
	}

	for key := range conflicts {
		conflicts[key] = uniqueSorted(conflicts[key])
	}
	return conflicts
}

func printSANConflicts(conflicts map[string][]string) {
	if len(conflicts) == 0 {
		return
	}
	names := make([]string, 0, len(conflicts))
	for name := range conflicts {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fmt.Printf("[warn] active SAN overlap with %s: %s\n", name, strings.Join(conflicts[name], ", "))
	}
}

func splitCSVNames(csv string) []string {
	var out []string
	for part := range strings.SplitSeq(csv, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func uniqueSorted(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
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
