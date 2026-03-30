package cmd

import (
	"fmt"
	"time"

	"certctl/internal/server"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var listen string
	var csrSubmitPassword string
	var csrMaxBodyBytes int64
	var csrMinInterval time.Duration

	cmd := &cobra.Command{
		Use:   "serve-certs",
		Short: "Serve certificate shares and CSR submission endpoints over HTTP",
		RunE: func(cmd *cobra.Command, args []string) error {
			csrSubmitPassword, err := util.ResolveSecretValue(csrSubmitPassword, "CERTCTL_CSR_SUBMIT_PASSWORD")
			if err != nil {
				return err
			}
			srv := server.New(server.Config{
				DBPath:            rootCfg.DBPath,
				Listen:            listen,
				CSRSubmitPassword: csrSubmitPassword,
				CSRMaxBodyBytes:   csrMaxBodyBytes,
				CSRMinInterval:    csrMinInterval,
			})
			fmt.Printf("Serving cert shares on %s\n", listen)
			if csrSubmitPassword != "" {
				fmt.Println("CSR submission endpoint enabled at /csr-requests")
			}
			return srv.Run()
		},
	}

	cmd.Flags().StringVar(&listen, "listen", ":8080", "listen address")
	cmd.Flags().StringVar(&csrSubmitPassword, "csr-submit-password", "", "optional password required for HTTP CSR submission")
	cmd.Flags().Int64Var(&csrMaxBodyBytes, "csr-max-body-bytes", 1<<20, "maximum HTTP CSR submission body size in bytes")
	cmd.Flags().DurationVar(&csrMinInterval, "csr-min-submit-interval", 2*time.Second, "minimum time between CSR submissions from the same client IP")
	rootCmd.AddCommand(cmd)
}
