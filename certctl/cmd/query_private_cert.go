package cmd

import (
	"fmt"

	"certctl/internal/cli"
	"certctl/internal/storage"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var commonName string
	var keyPassword string
	var storagePassword string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "query-private-cert",
		Short: "Decrypt and print a stored private leaf certificate and key",
		RunE: func(cmd *cobra.Command, args []string) error {
			cryptoPassword, err := util.ResolveCryptoPassword(keyPassword, storagePassword)
			if err != nil {
				return err
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := store.GetPrivateCertByNameOrSAN(commonName)
			if err != nil {
				return fmt.Errorf("no private certificate found for common name: %s", commonName)
			}

			certPEM := rec.CertPEM
			keyPEM, err := cli.Decrypt(rec.KeyPEM, cryptoPassword)
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(map[string]any{
					"id":                 rec.ID,
					"intermediate_ca_id": rec.IntermediateCAID,
					"common_name":        rec.CommonName,
					"sans_csv":           rec.SANsCSV,
					"cert_type":          rec.CertType,
					"key_type":           rec.KeyType,
					"issuer":             rec.Issuer,
					"status":             rec.Status,
					"supersedes_cert_id": rec.SupersedesCertID,
					"revoked_at":         formatTimeValue(rec.RevokedAt),
					"not_before":         formatTimeValue(rec.NotBefore),
					"not_after":          formatTimeValue(rec.NotAfter),
					"certificate_pem":    string(certPEM),
					"private_key_pem":    string(keyPEM),
				})
			}

			fmt.Printf("id: %s\n", rec.ID)
			fmt.Printf("commonName: %s\n", rec.CommonName)
			fmt.Printf("status: %s\n", rec.Status)
			fmt.Printf("sans: %s\n", rec.SANsCSV)
			fmt.Printf("certType: %s\n", rec.CertType)
			fmt.Printf("keyType: %s\n", rec.KeyType)
			fmt.Printf("issuer: %s\n", rec.Issuer)
			fmt.Printf("\n%s\n", certPEM)
			fmt.Printf("%s\n", keyPEM)

			return nil
		},
	}

	cmd.Flags().StringVar(&commonName, "common-name", "", "common name or SAN to find the private certificate")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "per-certificate encryption password")
	cmd.Flags().StringVar(&storagePassword, "storage-password", "", "fallback encryption password")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("common-name")

	rootCmd.AddCommand(cmd)
}
