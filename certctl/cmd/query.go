package cmd

import (
	"database/sql"
	"fmt"
	"time"

	"certctl/internal/cli"
	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var domain, password string
	var showKey bool

	cmd := &cobra.Command{
		Use:   "query",
		Short: "Read a stored certificate from SQLite and decrypt it",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()
			// rec, err := store.Get(domain)
			rec, err := store.GetByDomain(domain)
			if err != nil {
				if err == sql.ErrNoRows {
					return fmt.Errorf("no certificate found for domain: %s", domain)
				}
				return err
			}
			certPEM := rec.CertPEM
			printKV("domain", rec.Domain)
			printKV("provider", rec.Provider)
			printKV("email", rec.Email)
			printKV("issuer", rec.Issuer)
			if !rec.NotBefore.IsZero() {
				printKV("not before", rec.NotBefore.Format(time.RFC3339))
			}
			if !rec.NotAfter.IsZero() {
				printKV("not after", rec.NotAfter.Format(time.RFC3339))
			}
			fmt.Println("--- CERTIFICATE ---")
			fmt.Print(string(certPEM))
			if showKey {
				keyPEM, err := cli.Decrypt(rec.KeyPEM, password)
				if err != nil {
					return fmt.Errorf("failed to decrypt private key: %w", err)
				}
				fmt.Println("--- PRIVATE KEY ---")
				fmt.Print(string(keyPEM))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "target domain")
	cmd.Flags().StringVar(&password, "password", "", "encryption password")
	cmd.Flags().BoolVar(&showKey, "show-key", false, "also print the private key")
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("password")
	rootCmd.AddCommand(cmd)
}
