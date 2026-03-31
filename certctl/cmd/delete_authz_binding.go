package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var id string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "delete-authz-binding",
		Short: "Delete an authorization binding for a JWT principal",
		Example: `  certctl delete-authz-binding --id binding-id
  certctl delete-authz-binding --id binding-id --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := store.GetAuthzBindingByID(id)
			if err != nil {
				return err
			}
			if err := store.DeleteAuthzBinding(id); err != nil {
				return err
			}

			logAuditEvent(store, "delete_authz_binding", "authz_binding", rec.ID, fmt.Sprintf("deleted authz binding %s", rec.ID))
			if jsonOut {
				return printJSON(authzBindingPayload(rec))
			}

			fmt.Printf("Deleted authz binding %s\n", rec.ID)
			printKV("principal", rec.Principal)
			printKV("permission", rec.Permission)
			return nil
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "binding ID to delete")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("id")
	rootCmd.AddCommand(cmd)
}
