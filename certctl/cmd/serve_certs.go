package cmd

import (
	"fmt"
	"strings"
	"time"

	"certctl/internal/server"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var listen string
	var tlsCertFile string
	var tlsKeyFile string
	var nacl []string
	var csrSubmitPassword string
	var csrMaxBodyBytes int64
	var csrMinInterval time.Duration
	var adminUsername string
	var adminPassword string
	var adminWarnDays int
	var enableMetrics bool

	cmd := &cobra.Command{
		Use:   "serve-certs",
		Short: "Serve certificate shares, CSR endpoints, and optional admin API over HTTP or HTTPS",
		RunE: func(cmd *cobra.Command, args []string) error {
			csrSubmitPassword, err := util.ResolveSecretValue(csrSubmitPassword, "CERTCTL_CSR_SUBMIT_PASSWORD")
			if err != nil {
				return err
			}
			adminPassword, err := util.ResolveSecretValue(adminPassword, "CERTCTL_ADMIN_PASSWORD")
			if err != nil {
				return err
			}
			if (strings.TrimSpace(adminUsername) == "") != (adminPassword == "") {
				return fmt.Errorf("both --admin-username and --admin-password are required to enable the admin api")
			}
			srv := server.New(server.Config{
				DBPath:                  rootCfg.DBPath,
				Listen:                  listen,
				TLSCertFile:             tlsCertFile,
				TLSKeyFile:              tlsKeyFile,
				AllowCIDRs:              nacl,
				CSRSubmitPassword:       csrSubmitPassword,
				CSRMaxBodyBytes:         csrMaxBodyBytes,
				CSRMinInterval:          csrMinInterval,
				AdminUsername:           adminUsername,
				AdminPassword:           adminPassword,
				AdminWarnDays:           adminWarnDays,
				DefaultIntermediateName: rootCfg.DefaultIntermediateName,
				ProviderHTTPTimeout:     rootCfg.HTTPTimeout,
				EnableMetrics:           enableMetrics,
			})
			scheme := "http"
			if strings.TrimSpace(tlsCertFile) != "" || strings.TrimSpace(tlsKeyFile) != "" {
				scheme = "https"
			}
			fmt.Printf("Serving cert shares on %s://%s\n", scheme, listen)
			if len(nacl) > 0 {
				fmt.Printf("Allowing client networks: %s\n", strings.Join(nacl, ", "))
			}
			if csrSubmitPassword != "" {
				fmt.Println("CSR submission endpoint enabled at /csr-requests")
			}
			if strings.TrimSpace(adminUsername) != "" && adminPassword != "" {
				fmt.Println("Admin API enabled at /admin/v1 with HTTP Basic auth")
			}
			if enableMetrics {
				if strings.TrimSpace(adminUsername) != "" && adminPassword != "" {
					fmt.Println("Prometheus metrics enabled at /metrics with HTTP Basic auth")
				} else {
					fmt.Println("Prometheus metrics enabled at /metrics")
				}
			}
			return srv.Run()
		},
	}

	cmd.Flags().StringVar(&listen, "listen", ":8080", "listen address")
	cmd.Flags().StringVar(&tlsCertFile, "tls-cert-file", "", "optional TLS certificate PEM file for HTTPS")
	cmd.Flags().StringVar(&tlsKeyFile, "tls-key-file", "", "optional TLS private key PEM file for HTTPS")
	cmd.Flags().StringSliceVar(&nacl, "nacl", []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}, "allowed client IPv4 or IPv6 networks as CIDR values; repeat or comma-separate to override the default private ranges")
	cmd.Flags().StringVar(&csrSubmitPassword, "csr-submit-password", "", "optional password required for HTTP CSR submission")
	cmd.Flags().Int64Var(&csrMaxBodyBytes, "csr-max-body-bytes", 1<<20, "maximum HTTP CSR submission body size in bytes")
	cmd.Flags().DurationVar(&csrMinInterval, "csr-min-submit-interval", 2*time.Second, "minimum time between CSR submissions from the same client IP")
	cmd.Flags().StringVar(&adminUsername, "admin-username", "", "optional HTTP Basic auth username for the admin API")
	cmd.Flags().StringVar(&adminPassword, "admin-password", "", "optional HTTP Basic auth password for the admin API")
	cmd.Flags().IntVar(&adminWarnDays, "admin-warn-days", 30, "doctor and metrics warning window in days for the admin API")
	cmd.Flags().BoolVar(&enableMetrics, "metrics", false, "enable Prometheus-style metrics at /metrics")
	rootCmd.AddCommand(cmd)
}
