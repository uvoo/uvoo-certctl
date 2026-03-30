package cmd

import (
	"fmt"

	"certctl/internal/ops"
	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var id string
	var reason string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:     "reject-csr",
		Short:   "Reject a queued CSR request",
		Example: `  certctl reject-csr --id <request-id> --reason "unable to verify requester"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if reason == "" {
				return fmt.Errorf("--reason is required")
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if err := ops.RejectCSRRequest(store, id, reason); err != nil {
				return err
			}
			if jsonOut {
				return printJSON(map[string]any{
					"id":            id,
					"status":        storage.CSRStatusRejected,
					"decision_note": reason,
				})
			}

			fmt.Printf("Rejected CSR request %s\n", id)
			return nil
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "csr request id")
	cmd.Flags().StringVar(&reason, "reason", "", "rejection reason")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("id")
	rootCmd.AddCommand(cmd)
}
