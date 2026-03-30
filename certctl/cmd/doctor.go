package cmd

import (
	"fmt"
	"strings"
	"time"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

type doctorFinding struct {
	Severity string `json:"severity"`
	Check    string `json:"check"`
	Message  string `json:"message"`
}

func init() {
	var jsonOut bool
	var warnDays int

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run read-only validation checks against the certificate database",
		Example: `  certctl doctor
  certctl doctor --json
  certctl doctor --warn-days 14`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			findings, err := runDoctor(store, warnDays)
			if err != nil {
				return err
			}

			status := "ok"
			for _, finding := range findings {
				if finding.Severity == "error" {
					status = "error"
					break
				}
				if finding.Severity == "warn" && status == "ok" {
					status = "warn"
				}
			}

			if jsonOut {
				return printJSON(map[string]any{
					"status":   status,
					"findings": findings,
				})
			}

			if len(findings) == 0 {
				fmt.Println("doctor: ok")
				return nil
			}

			fmt.Printf("doctor: %s\n", status)
			for _, finding := range findings {
				fmt.Printf("[%s] %s: %s\n", finding.Severity, finding.Check, finding.Message)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	cmd.Flags().IntVar(&warnDays, "warn-days", 30, "warn when active certificates, CAs, shares, or pending CSRs are within this many days of expiry or staleness")
	rootCmd.AddCommand(cmd)
}

type doctorStore interface {
	List(string, bool) ([]storage.PublicCert, error)
	ListPrivateCerts(string, bool) ([]storage.PrivateCert, error)
	ListPrivateRootCAs(string, bool) ([]storage.PrivateRootCA, error)
	ListPrivateIntermediateCAs(string, bool) ([]storage.PrivateIntermediateCA, error)
	ListShares(string) ([]storage.CertShare, error)
	ListCSRRequests(string, string) ([]storage.CSRRequest, error)
}

func runDoctor(store doctorStore, warnDays int) ([]doctorFinding, error) {
	now := time.Now().UTC()
	warnWindow := time.Duration(warnDays) * 24 * time.Hour
	var findings []doctorFinding

	publicRows, err := store.List("", true)
	if err != nil {
		return nil, err
	}
	privateRows, err := store.ListPrivateCerts("", true)
	if err != nil {
		return nil, err
	}
	rootRows, err := store.ListPrivateRootCAs("", true)
	if err != nil {
		return nil, err
	}
	icaRows, err := store.ListPrivateIntermediateCAs("", true)
	if err != nil {
		return nil, err
	}
	shares, err := store.ListShares("")
	if err != nil {
		return nil, err
	}
	pendingCSRs, err := store.ListCSRRequests("", storage.CSRStatusPending)
	if err != nil {
		return nil, err
	}

	findings = append(findings, checkActiveLeafCounts(publicRows, privateRows)...)
	findings = append(findings, checkLeafLineageLinks(publicRows, privateRows)...)
	findings = append(findings, checkCAInvariants(rootRows, icaRows, now)...)
	findings = append(findings, checkPrivateCertIssuers(privateRows, icaRows)...)
	if warnDays > 0 {
		findings = append(findings, checkExpiringLeafs(publicRows, privateRows, now, warnWindow)...)
		findings = append(findings, checkExpiringCAs(rootRows, icaRows, now, warnWindow)...)
		findings = append(findings, checkShares(shares, now, warnWindow)...)
		findings = append(findings, checkPendingCSRRequests(pendingCSRs, now, warnWindow)...)
	}

	return findings, nil
}

func checkActiveLeafCounts(publicRows []storage.PublicCert, privateRows []storage.PrivateCert) []doctorFinding {
	var findings []doctorFinding
	publicCounts := map[string]int{}
	for _, row := range publicRows {
		if row.Status == storage.StatusActive {
			publicCounts[row.CommonName]++
		}
	}
	for commonName, count := range publicCounts {
		if count > 1 {
			findings = append(findings, doctorFinding{
				Severity: "error",
				Check:    "public_active_count",
				Message:  fmt.Sprintf("%s has %d active public certs", commonName, count),
			})
		}
	}

	privateCounts := map[string]int{}
	for _, row := range privateRows {
		if row.Status == storage.StatusActive {
			privateCounts[row.CommonName]++
		}
	}
	for commonName, count := range privateCounts {
		if count > 1 {
			findings = append(findings, doctorFinding{
				Severity: "error",
				Check:    "private_active_count",
				Message:  fmt.Sprintf("%s has %d active private certs", commonName, count),
			})
		}
	}
	return findings
}

func checkLeafLineageLinks(publicRows []storage.PublicCert, privateRows []storage.PrivateCert) []doctorFinding {
	var findings []doctorFinding

	publicIDs := map[string]struct{}{}
	for _, row := range publicRows {
		publicIDs[row.ID] = struct{}{}
	}
	for _, row := range publicRows {
		if row.SupersedesCertID != "" {
			if _, ok := publicIDs[row.SupersedesCertID]; !ok {
				findings = append(findings, doctorFinding{
					Severity: "error",
					Check:    "public_lineage",
					Message:  fmt.Sprintf("public cert %s supersedes missing cert %s", row.ID, row.SupersedesCertID),
				})
			}
		}
	}

	privateIDs := map[string]struct{}{}
	for _, row := range privateRows {
		privateIDs[row.ID] = struct{}{}
	}
	for _, row := range privateRows {
		if row.SupersedesCertID != "" {
			if _, ok := privateIDs[row.SupersedesCertID]; !ok {
				findings = append(findings, doctorFinding{
					Severity: "error",
					Check:    "private_lineage",
					Message:  fmt.Sprintf("private cert %s supersedes missing cert %s", row.ID, row.SupersedesCertID),
				})
			}
		}
	}

	return findings
}

func checkCAInvariants(rootRows []storage.PrivateRootCA, icaRows []storage.PrivateIntermediateCA, now time.Time) []doctorFinding {
	var findings []doctorFinding

	rootActive := map[string]int{}
	for _, row := range rootRows {
		if row.Status == storage.StatusActive {
			rootActive[row.Name]++
		}
		if row.IsIssuing && !row.NotAfter.IsZero() && row.NotAfter.Before(now) {
			findings = append(findings, doctorFinding{
				Severity: "error",
				Check:    "root_expired_issuing",
				Message:  fmt.Sprintf("root CA %s is issuing but expired at %s", row.ID, formatTimeValue(row.NotAfter)),
			})
		}
		if row.Status != storage.StatusActive && row.IsIssuing {
			findings = append(findings, doctorFinding{
				Severity: "warn",
				Check:    "root_non_active_issuing",
				Message:  fmt.Sprintf("root CA %s has status %s but is_issuing=true", row.ID, row.Status),
			})
		}
	}
	for name, count := range rootActive {
		if count > 1 {
			findings = append(findings, doctorFinding{
				Severity: "error",
				Check:    "root_active_count",
				Message:  fmt.Sprintf("root logical name %s has %d active rows", name, count),
			})
		}
	}

	icaActive := map[string]int{}
	rootIDs := map[string]struct{}{}
	for _, row := range rootRows {
		rootIDs[row.ID] = struct{}{}
	}
	for _, row := range icaRows {
		if row.Status == storage.StatusActive {
			icaActive[row.Name]++
		}
		if row.IsIssuing && !row.NotAfter.IsZero() && row.NotAfter.Before(now) {
			findings = append(findings, doctorFinding{
				Severity: "error",
				Check:    "intermediate_expired_issuing",
				Message:  fmt.Sprintf("intermediate CA %s is issuing but expired at %s", row.ID, formatTimeValue(row.NotAfter)),
			})
		}
		if row.Status != storage.StatusActive && row.IsIssuing {
			findings = append(findings, doctorFinding{
				Severity: "warn",
				Check:    "intermediate_non_active_issuing",
				Message:  fmt.Sprintf("intermediate CA %s has status %s but is_issuing=true", row.ID, row.Status),
			})
		}
		if _, ok := rootIDs[row.RootCAID]; !ok {
			findings = append(findings, doctorFinding{
				Severity: "error",
				Check:    "intermediate_root_ref",
				Message:  fmt.Sprintf("intermediate CA %s references missing root %s", row.ID, row.RootCAID),
			})
		}
	}
	for name, count := range icaActive {
		if count > 1 {
			findings = append(findings, doctorFinding{
				Severity: "error",
				Check:    "intermediate_active_count",
				Message:  fmt.Sprintf("intermediate logical name %s has %d active rows", name, count),
			})
		}
	}

	return findings
}

func checkPrivateCertIssuers(privateRows []storage.PrivateCert, icaRows []storage.PrivateIntermediateCA) []doctorFinding {
	var findings []doctorFinding
	icaByID := map[string]storage.PrivateIntermediateCA{}
	for _, row := range icaRows {
		icaByID[row.ID] = row
	}

	for _, row := range privateRows {
		if row.Status != storage.StatusActive {
			continue
		}
		ica, ok := icaByID[row.IntermediateCAID]
		if !ok {
			findings = append(findings, doctorFinding{
				Severity: "error",
				Check:    "private_issuer_ref",
				Message:  fmt.Sprintf("private cert %s references missing intermediate %s", row.ID, row.IntermediateCAID),
			})
			continue
		}
		if ica.Status != storage.StatusActive {
			findings = append(findings, doctorFinding{
				Severity: "warn",
				Check:    "private_inactive_issuer",
				Message:  fmt.Sprintf("active private cert %s is linked to intermediate %s with status %s", row.ID, ica.ID, ica.Status),
			})
		}
		if !strings.Contains(strings.ToLower(row.Issuer), strings.ToLower(ica.CommonName)) && row.Issuer != "" {
			findings = append(findings, doctorFinding{
				Severity: "warn",
				Check:    "private_issuer_name",
				Message:  fmt.Sprintf("private cert %s issuer %q does not appear to match intermediate %s (%s)", row.ID, row.Issuer, ica.ID, ica.CommonName),
			})
		}
	}

	return findings
}

func checkExpiringLeafs(publicRows []storage.PublicCert, privateRows []storage.PrivateCert, now time.Time, warnWindow time.Duration) []doctorFinding {
	var findings []doctorFinding

	for _, row := range publicRows {
		if row.Status != storage.StatusActive || row.NotAfter.IsZero() {
			continue
		}
		if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
			findings = append(findings, doctorFinding{
				Severity: "warn",
				Check:    "public_expiring",
				Message:  fmt.Sprintf("public cert %s (%s) expires in %s at %s", row.ID, row.CommonName, describeRemaining(remaining), formatTimeValue(row.NotAfter)),
			})
		}
	}

	for _, row := range privateRows {
		if row.Status != storage.StatusActive || row.NotAfter.IsZero() {
			continue
		}
		if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
			findings = append(findings, doctorFinding{
				Severity: "warn",
				Check:    "private_expiring",
				Message:  fmt.Sprintf("private cert %s (%s) expires in %s at %s", row.ID, row.CommonName, describeRemaining(remaining), formatTimeValue(row.NotAfter)),
			})
		}
	}

	return findings
}

func checkExpiringCAs(rootRows []storage.PrivateRootCA, icaRows []storage.PrivateIntermediateCA, now time.Time, warnWindow time.Duration) []doctorFinding {
	var findings []doctorFinding

	for _, row := range rootRows {
		if row.Status != storage.StatusActive || row.NotAfter.IsZero() {
			continue
		}
		if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
			findings = append(findings, doctorFinding{
				Severity: "warn",
				Check:    "root_expiring",
				Message:  fmt.Sprintf("root CA %s (%s) expires in %s at %s", row.ID, row.Name, describeRemaining(remaining), formatTimeValue(row.NotAfter)),
			})
		}
	}

	for _, row := range icaRows {
		if row.Status != storage.StatusActive || row.NotAfter.IsZero() {
			continue
		}
		if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
			findings = append(findings, doctorFinding{
				Severity: "warn",
				Check:    "intermediate_expiring",
				Message:  fmt.Sprintf("intermediate CA %s (%s) expires in %s at %s", row.ID, row.Name, describeRemaining(remaining), formatTimeValue(row.NotAfter)),
			})
		}
	}

	return findings
}

func checkShares(shares []storage.CertShare, now time.Time, warnWindow time.Duration) []doctorFinding {
	var findings []doctorFinding

	for _, sh := range shares {
		if !sh.RevokedAt.IsZero() || sh.ExpiresAt.IsZero() {
			continue
		}
		switch remaining := sh.ExpiresAt.Sub(now); {
		case remaining <= 0:
			findings = append(findings, doctorFinding{
				Severity: "warn",
				Check:    "share_expired",
				Message:  fmt.Sprintf("share %s for cert %s expired at %s", sh.ID, sh.CertID, formatTimeValue(sh.ExpiresAt)),
			})
		case remaining <= warnWindow:
			findings = append(findings, doctorFinding{
				Severity: "warn",
				Check:    "share_expiring",
				Message:  fmt.Sprintf("share %s for cert %s expires in %s at %s", sh.ID, sh.CertID, describeRemaining(remaining), formatTimeValue(sh.ExpiresAt)),
			})
		}
	}

	return findings
}

func checkPendingCSRRequests(requests []storage.CSRRequest, now time.Time, warnWindow time.Duration) []doctorFinding {
	var findings []doctorFinding

	for _, req := range requests {
		if req.Status != storage.CSRStatusPending || req.CreatedAt.IsZero() {
			continue
		}
		age := now.Sub(req.CreatedAt)
		if age >= warnWindow {
			findings = append(findings, doctorFinding{
				Severity: "warn",
				Check:    "csr_pending_age",
				Message:  fmt.Sprintf("pending %s CSR %s (%s) is %s old", req.Kind, req.ID, req.CommonName, describeRemaining(age)),
			})
		}
	}

	return findings
}

func describeRemaining(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int(d.Round(24*time.Hour) / (24 * time.Hour))
	if days <= 0 {
		return "less than 1 day"
	}
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}
