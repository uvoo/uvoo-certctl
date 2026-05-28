package cmd

import (
	"fmt"

	"uvoocertctl/internal/ops"
	"uvoocertctl/internal/storage"
	"github.com/spf13/cobra"
)

type doctorFinding = ops.DoctorFinding
type doctorStore = ops.DoctorStore

func init() {
	var jsonOut bool
	var warnDays int
	var authOnly bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run read-only validation checks against the certificate database",
		Example: `  uvoocertctl doctor
  uvoocertctl doctor --json
  uvoocertctl doctor --warn-days 14
  uvoocertctl doctor --auth-only --json`,
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
			if authOnly {
				findings = ops.AuthRelatedDoctorFindings(findings)
			}

			status := ops.DoctorStatus(findings)
			if jsonOut {
				return printJSON(map[string]any{
					"status":    status,
					"auth_only": authOnly,
					"findings":  findings,
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
	cmd.Flags().BoolVar(&authOnly, "auth-only", false, "only include auth-related validation findings")
	cmd.Flags().IntVar(&warnDays, "warn-days", 30, "warn when active certificates, CAs, shares, or pending CSRs are within this many days of expiry or staleness")
	rootCmd.AddCommand(cmd)
}

func runDoctor(store doctorStore, warnDays int) ([]doctorFinding, error) {
	return runDoctorWithOptions(store, ops.DoctorOptions{
		WarnDays:        warnDays,
		AuthIssuerProbe: ops.DefaultAuthIssuerProbe(rootCfg.HTTPTimeout),
	})
}

func runDoctorWithOptions(store doctorStore, opts ops.DoctorOptions) ([]doctorFinding, error) {
	return ops.RunDoctorWithOptions(store, opts)
}
