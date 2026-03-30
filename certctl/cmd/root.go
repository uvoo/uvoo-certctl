package cmd

import (
	"fmt"
	"os"
	"time"

	"certctl/internal/util"
	"github.com/spf13/cobra"
)

var rootCfg struct {
	DBPath                  string
	HTTPTimeout             time.Duration
	DefaultRootCAName       string
	DefaultIntermediateName string
}

var rootCmd = &cobra.Command{
	Use:   "certctl",
	Short: "Manage public and private certificate issuance, storage, and sharing",
	Example: `  certctl doctor
  certctl version --json
  certctl create-root-ca --name corp-root --common-name "Corp Root CA"
  certctl backup-db --out certctl-backup.db`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&rootCfg.DBPath, "db", util.EnvOrDefault("CERT_DB", "certs.db"), "sqlite database path")
	rootCmd.PersistentFlags().DurationVar(&rootCfg.HTTPTimeout, "http-timeout", 45*time.Second, "HTTP timeout for provider API calls")
	rootCmd.PersistentFlags().StringVar(&rootCfg.DefaultRootCAName, "default-root-ca", util.EnvOrDefault("CERTCTL_DEFAULT_ROOT_CA", ""), "default root CA logical name")
	rootCmd.PersistentFlags().StringVar(&rootCfg.DefaultIntermediateName, "default-intermediate-ca", util.EnvOrDefault("CERTCTL_DEFAULT_INTERMEDIATE_CA", ""), "default intermediate CA logical name")
}
