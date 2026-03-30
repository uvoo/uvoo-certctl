package cmd

import (
	"fmt"

	"certctl/internal/server"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var listen string
	var csrSubmitPassword string

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
	rootCmd.AddCommand(cmd)
}
