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

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run read-only validation checks against the certificate database",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			findings, err := runDoctor(store)
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
	rootCmd.AddCommand(cmd)
}

type doctorStore interface {
	List(string, bool) ([]storage.PublicCert, error)
	ListPrivateCerts(string, bool) ([]storage.PrivateCert, error)
	ListPrivateRootCAs(string, bool) ([]storage.PrivateRootCA, error)
	ListPrivateIntermediateCAs(string, bool) ([]storage.PrivateIntermediateCA, error)
}

func runDoctor(store doctorStore) ([]doctorFinding, error) {
	now := time.Now().UTC()
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

	findings = append(findings, checkActiveLeafCounts(publicRows, privateRows)...)
	findings = append(findings, checkLeafLineageLinks(publicRows, privateRows)...)
	findings = append(findings, checkCAInvariants(rootRows, icaRows, now)...)
	findings = append(findings, checkPrivateCertIssuers(privateRows, icaRows)...)

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
