package cmd

import (
	"fmt"
	"time"

	"certctl/internal/acme"
	"certctl/internal/cli"
	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var domain string
	var password string
	var force bool
	var days int

	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew a stored certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := store.Get(domain)
			if err != nil {
				return err
			}

			remaining := time.Until(rec.NotAfter)
			if !force && remaining > time.Duration(days)*24*time.Hour {
				fmt.Printf("Skipping renewal for %s (expires %s)\n", domain, rec.NotAfter.Format(time.RFC3339))
				return nil
			}

			certs, err := acme.Issue(cmd.Context(), acme.IssueOptions{
				Email:       rec.Email,
				Domains:     []string{domain},
				Provider:    rec.Provider,
				Timeout:     10 * time.Minute,
				Propagation: 30 * time.Minute,
			})
			if err != nil {
				return err
			}

			encCert, err := cli.Encrypt(certs.Certificate, password)
			if err != nil {
				return err
			}
			encKey, err := cli.Encrypt(certs.PrivateKey, password)
			if err != nil {
				return err
			}

			issuer, notBefore, notAfter, err := storage.ParseCertMetadata(certs.Certificate)
			if err != nil {
				return err
			}

			rec.CertPEM = encCert
			rec.KeyPEM = encKey
			rec.Issuer = issuer
			rec.NotBefore = notBefore
			rec.NotAfter = notAfter

			if err := store.Upsert(rec); err != nil {
				return err
			}

			fmt.Printf("Renewed certificate for %s\n", domain)
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "domain to renew")
	cmd.Flags().StringVar(&password, "password", "", "encryption password")
	cmd.Flags().BoolVar(&force, "force", false, "renew even if not near expiry")
	cmd.Flags().IntVar(&days, "days", 30, "renew if expires within this many days")
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("password")

	rootCmd.AddCommand(cmd)
}
