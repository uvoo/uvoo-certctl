package cmd

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"uvoo-certctl/internal/cli"
	"uvoo-certctl/internal/storage"
	"uvoo-certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var san, password string
	var showKey bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "query",
		Short: "Read a stored certificate from SQLite and decrypt it",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()
			rec, err := store.GetBySAN(san)
			if err != nil {
				if err == sql.ErrNoRows {
					return fmt.Errorf("no certificate found for san or common_name: %s", san)
				}
				return err
			}
			if showKey && strings.TrimSpace(password) == "" {
				return fmt.Errorf("--password is required when --show-key is set")
			}
			password, err = util.ResolveSecretValue(password, "CERTCTL_KEY_PASSWORD", "CERTCTL_STORAGE_PASSWORD")
			if err != nil {
				return err
			}
			certPEM := rec.CertPEM
			if jsonOut {
				payload := map[string]any{
					"id":                 rec.ID,
					"common_name":        rec.CommonName,
					"sans_csv":           rec.SANsCSV,
					"provider":           rec.Provider,
					"email":              rec.Email,
					"issuer":             rec.Issuer,
					"status":             rec.Status,
					"supersedes_cert_id": rec.SupersedesCertID,
					"revoked_at":         formatTimeValue(rec.RevokedAt),
					"not_before":         formatTimeValue(rec.NotBefore),
					"not_after":          formatTimeValue(rec.NotAfter),
					"certificate_pem":    string(certPEM),
					"private_key_stored": privateKeyStored(rec.KeyPEM),
				}
				if showKey {
					if !privateKeyStored(rec.KeyPEM) {
						return fmt.Errorf("private key is not stored for csr-based certificate %s", rec.CommonName)
					}
					keyPEM, err := cli.Decrypt(rec.KeyPEM, password)
					if err != nil {
						return fmt.Errorf("failed to decrypt private key: %w", err)
					}
					payload["private_key_pem"] = string(keyPEM)
				}
				return printJSON(payload)
			}
			printKV("id", rec.ID)
			printKV("common_name", rec.CommonName)
			printKV("status", rec.Status)
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
				if !privateKeyStored(rec.KeyPEM) {
					return fmt.Errorf("private key is not stored for csr-based certificate %s", rec.CommonName)
				}
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
	cmd.Flags().StringVar(&san, "san", "", "target san")
	cmd.Flags().StringVar(&password, "password", "", "encryption password")
	cmd.Flags().BoolVar(&showKey, "show-key", false, "also print the private key")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("san")
	rootCmd.AddCommand(cmd)
}
