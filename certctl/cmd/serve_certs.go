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

	cmd := &cobra.Command{
		Use:   "serve-certs",
		Short: "Serve certificate shares and CSR submission endpoints over HTTP or HTTPS",
		RunE: func(cmd *cobra.Command, args []string) error {
			csrSubmitPassword, err := util.ResolveSecretValue(csrSubmitPassword, "CERTCTL_CSR_SUBMIT_PASSWORD")
			if err != nil {
				return err
			}
			srv := server.New(server.Config{
				DBPath:            rootCfg.DBPath,
				Listen:            listen,
				TLSCertFile:       tlsCertFile,
				TLSKeyFile:        tlsKeyFile,
				AllowCIDRs:        nacl,
				CSRSubmitPassword: csrSubmitPassword,
				CSRMaxBodyBytes:   csrMaxBodyBytes,
				CSRMinInterval:    csrMinInterval,
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
	rootCmd.AddCommand(cmd)
}
