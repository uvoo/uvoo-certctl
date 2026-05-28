package cmd

import (
	"fmt"
	"strings"
	"time"

	"uvoocertctl/internal/acme"
	"uvoocertctl/internal/cli"
	"uvoocertctl/internal/storage"
	"uvoocertctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var commonName string
	var password string
	var force bool
	var days int
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew a stored certificate",
		Example: `  uvoocertctl renew --common-name api.example.com
  uvoocertctl renew --common-name api.example.com --force --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := util.ResolveSecretValue(password, "CERTCTL_KEY_PASSWORD", "CERTCTL_STORAGE_PASSWORD")
			if err != nil {
				return err
			}
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			// rec, err := store.Get(domain)
			rec, err := store.GetByCommonName(commonName)
			if err != nil {
				return err
			}

			remaining := time.Until(rec.NotAfter)
			if !force && remaining > time.Duration(days)*24*time.Hour {
				if jsonOut {
					return printJSON(map[string]any{
						"common_name": commonName,
						"status":      "skipped",
						"not_after":   formatTimeValue(rec.NotAfter),
					})
				}
				fmt.Printf("Skipping renewal for %s (expires %s)\n", commonName, rec.NotAfter.Format(time.RFC3339))
				return nil
			}
			sans := strings.Split(rec.SANsCSV, ",")
			certs, err := acme.Issue(cmd.Context(), acme.IssueOptions{
				Email: rec.Email,
				// Domains:     []string{domain},
				// Domains:     []string{sans},
				// SANs:     sans,
				Domains:     sans,
				Provider:    rec.Provider,
				Timeout:     10 * time.Minute,
				Propagation: 30 * time.Minute,
			})
			if err != nil {
				return err
			}

			/*
				encCert, err := cli.Encrypt(certs.Certificate, password)
				if err != nil {
					return err
				}
			*/
			encKey, err := cli.Encrypt(certs.PrivateKey, password)
			if err != nil {
				return err
			}

			issuer, notBefore, notAfter, err := storage.ParseCertMetadata(certs.Certificate)
			if err != nil {
				return err
			}

			rec.CertPEM = certs.Certificate
			rec.KeyPEM = encKey
			rec.Issuer = issuer
			rec.NotBefore = notBefore
			rec.NotAfter = notAfter

			if err := store.Upsert(rec); err != nil {
				return err
			}
			rec, err = store.GetByCommonName(commonName)
			if err != nil {
				return err
			}
			logAuditEvent(store, "renew_public_cert", "public_cert", rec.ID, rec.CommonName)
			if jsonOut {
				return printJSON(map[string]any{
					"id":          rec.ID,
					"common_name": rec.CommonName,
					"status":      rec.Status,
					"issuer":      rec.Issuer,
					"not_before":  formatTimeValue(rec.NotBefore),
					"not_after":   formatTimeValue(rec.NotAfter),
				})
			}

			fmt.Printf("Renewed certificate for %s\n", commonName)
			return nil
		},
	}

	cmd.Flags().StringVar(&commonName, "common-name", "", "common name to renew")
	cmd.Flags().StringVar(&commonName, "common_name", "", "deprecated alias for --common-name")
	cmd.Flags().StringVar(&password, "password", "", "encryption password")
	cmd.Flags().BoolVar(&force, "force", false, "renew even if not near expiry")
	cmd.Flags().IntVar(&days, "days", 30, "renew if expires within this many days")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.Flags().MarkDeprecated("common_name", "use --common-name instead")
	_ = cmd.Flags().MarkHidden("common_name")
	_ = cmd.MarkFlagRequired("common-name")
	rootCmd.AddCommand(cmd)
}
