package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"certctl/internal/cli"
	"certctl/internal/storage"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var commonName string
	var outDir string
	var keyPassword string
	var storagePassword string

	cmd := &cobra.Command{
		Use:   "export-private-cert",
		Short: "Decrypt and export a stored private certificate and key to files",
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

			if outDir == "" {
				outDir = "."
			}
			if err := os.MkdirAll(outDir, 0755); err != nil {
				return err
			}

			base := sanitizeFileBase(rec.CommonName)
			certPath := filepath.Join(outDir, base+".crt.pem")
			keyPath := filepath.Join(outDir, base+".key.pem")

			if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
				return err
			}
			if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
				return err
			}

			fmt.Printf("Exported certificate: %s\n", certPath)
			fmt.Printf("Exported private key: %s\n", keyPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&commonName, "common-name", "", "common name or SAN to find the private certificate")
	cmd.Flags().StringVar(&outDir, "out-dir", ".", "directory to write exported files")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "per-certificate encryption password")
	cmd.Flags().StringVar(&storagePassword, "storage-password", "", "fallback encryption password")
	_ = cmd.MarkFlagRequired("common-name")

	rootCmd.AddCommand(cmd)
}

func sanitizeFileBase(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "*", "wildcard")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}
