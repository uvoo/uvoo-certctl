package ops

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"uvoocertctl/internal/dns"
	"uvoocertctl/internal/privateca"
	"uvoocertctl/internal/storage"
	"uvoocertctl/internal/util"
)

type ProviderConfig struct {
	Provider    string
	APIUser     string
	APIKey      string
	ClientIP    string
	DNSResolver string
	HTTPTimeout time.Duration
}

type SANConflict struct {
	CommonName string
	SANs       []string
}

func (c ProviderConfig) dnsConfig() dns.Config {
	return dns.Config{
		Provider:    c.Provider,
		APIUser:     c.APIUser,
		APIKey:      c.APIKey,
		ClientIP:    c.ClientIP,
		HTTPTimeout: c.HTTPTimeout,
	}
}

func (c ProviderConfig) Validate() error {
	if err := util.Require("provider", c.Provider); err != nil {
		return err
	}
	if err := util.Require("api-user", c.APIUser); err != nil {
		return err
	}
	if err := util.Require("api-key", c.APIKey); err != nil {
		return err
	}
	if strings.EqualFold(c.Provider, "namecheap") {
		if err := util.Require("client-ip for namecheap", c.ClientIP); err != nil {
			return err
		}
	}
	return nil
}

func NewProvider(ctx context.Context, cfg ProviderConfig) (dns.Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	provider, err := dns.NewProvider(cfg.dnsConfig())
	if err != nil {
		return nil, err
	}
	_ = ctx
	return provider, nil
}

func WithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), timeout)
}

func LogAuditEvent(store *storage.Store, action, targetKind, targetID, summary string) {
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

func ListPublicSANConflicts(store *storage.Store, commonName string, sans []string) ([]SANConflict, error) {
	rows, err := store.List("", false)
	if err != nil {
		return nil, err
	}
	records := make([]sanRecord, 0, len(rows))
	for _, row := range rows {
		records = append(records, sanRecord{
			CommonName: row.CommonName,
			SANsCSV:    row.SANsCSV,
			Status:     row.Status,
		})
	}
	return collectSANConflicts(commonName, sans, records), nil
}

func ListPrivateSANConflicts(store *storage.Store, commonName string, sans []string) ([]SANConflict, error) {
	rows, err := store.ListPrivateCerts("", false)
	if err != nil {
		return nil, err
	}
	records := make([]sanRecord, 0, len(rows))
	for _, row := range rows {
		records = append(records, sanRecord{
			CommonName: row.CommonName,
			SANsCSV:    row.SANsCSV,
			Status:     row.Status,
		})
	}
	return collectSANConflicts(commonName, sans, records), nil
}

func BuildPublicSANSet(commonName string, sans []string, includeRoot bool) []string {
	seen := map[string]bool{}
	var out []string

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	add(commonName)
	for _, s := range sans {
		for part := range strings.SplitSeq(s, ",") {
			add(part)
		}
	}
	if includeRoot {
		var extra []string
		for _, d := range out {
			if after, ok := strings.CutPrefix(d, "*."); ok {
				extra = append(extra, after)
			}
		}
		for _, e := range extra {
			add(e)
		}
	}
	return out
}

func NormalizePrivateCertSANs(commonName string, sans []string) []string {
	seen := map[string]struct{}{}
	var out []string

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	add(commonName)
	for _, item := range sans {
		for part := range strings.SplitSeq(item, ",") {
			add(part)
		}
	}
	return out
}

func ParseCSRRequest(req storage.CSRRequest) (*x509.CertificateRequest, error) {
	csr, _, err := privateca.ParseCertificateRequest(req.CSRPEM)
	return csr, err
}

func PublicCSRNames(csr *x509.CertificateRequest) []string {
	names := make([]string, 0, len(csr.DNSNames)+1)
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" {
		names = append(names, cn)
	}
	names = append(names, csr.DNSNames...)
	return uniqueSorted(names)
}

func ValidatePublicCSR(csr *x509.CertificateRequest) error {
	if len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 || len(csr.IPAddresses) > 0 {
		return fmt.Errorf("public CSR requests only support DNS names")
	}
	names := PublicCSRNames(csr)
	if len(names) == 0 {
		return fmt.Errorf("public CSR request must include at least one DNS name")
	}
	for _, name := range names {
		if net.ParseIP(name) != nil {
			return fmt.Errorf("public CSR requests only support DNS names")
		}
	}
	return nil
}

func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func SplitSANCSV(csv string) []string {
	var out []string
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

type sanRecord struct {
	CommonName string
	SANsCSV    string
	Status     string
}

func collectSANConflicts(commonName string, sans []string, rows []sanRecord) []SANConflict {
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

	names := make([]string, 0, len(conflicts))
	for name := range conflicts {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]SANConflict, 0, len(names))
	for _, name := range names {
		out = append(out, SANConflict{
			CommonName: name,
			SANs:       uniqueSorted(conflicts[name]),
		})
	}
	return out
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
