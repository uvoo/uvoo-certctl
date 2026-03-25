package cmd

import (
	"fmt"
	"os"
	"time"

	"certctl/internal/util"
	"github.com/spf13/cobra"
)

var rootCfg struct {
	DBPath      string
	HTTPTimeout time.Duration
}

var rootCmd = &cobra.Command{
	Use:           "certctl",
	Short:         "Issue and manage ACME certificates with DNS providers",
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
}
