package cmd

import (
	"fmt"

	"uvoo-certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var kind string
	var id string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a stored certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			switch kind {
			case "public":
				err = store.RevokePublicCert(id)
			case "private":
				err = store.RevokePrivateCert(id)
			default:
				return fmt.Errorf("--kind must be public or private")
			}
			if err != nil {
				return err
			}
			logAuditEvent(store, "revoke", kind+"_cert", id, "")
			if jsonOut {
				return printJSON(map[string]any{
					"kind":   kind,
					"id":     id,
					"status": "revoked",
				})
			}

			fmt.Printf("Revoked %s certificate %s\n", kind, id)
			return nil
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "certificate kind: public or private")
	cmd.Flags().StringVar(&id, "id", "", "certificate ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("id")
	rootCmd.AddCommand(cmd)
}
