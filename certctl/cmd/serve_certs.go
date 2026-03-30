package cmd

import (
	"fmt"

	"certctl/internal/server"
	"github.com/spf13/cobra"
)

func init() {
	var listen string

	cmd := &cobra.Command{
		Use:   "serve-certs",
		Short: "Serve certificate shares over HTTP",
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := server.New(server.Config{
				DBPath: rootCfg.DBPath,
				Listen: listen,
			})
			fmt.Printf("Serving cert shares on %s\n", listen)
			return srv.Run()
		},
	}

	cmd.Flags().StringVar(&listen, "listen", ":8080", "listen address")
	rootCmd.AddCommand(cmd)
}
