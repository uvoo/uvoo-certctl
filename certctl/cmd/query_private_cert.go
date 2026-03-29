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

			rec, err := store.GetPrivateCertByName(commonName)
			if err != nil {
				return fmt.Errorf("no private certificate found for common name: %s", commonName)
			}

			certPEM, err := cli.Decrypt(rec.CertPEM, cryptoPassword)
			if err != nil {
				return err
			}
			keyPEM, err := cli.Decrypt(rec.KeyPEM, cryptoPassword)
			if err != nil {
				return err
			}

			fmt.Printf("id: %s\n", rec.ID)
			fmt.Printf("commonName: %s\n", rec.CommonName)
			fmt.Printf("domains: %s\n", rec.DomainsCSV)
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
	_ = cmd.MarkFlagRequired("common-name")

	rootCmd.AddCommand(cmd)
}
