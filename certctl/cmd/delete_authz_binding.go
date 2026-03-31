package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var id string
	var principal string
	var permission string
	var resourceKind string
	var resourceRef string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "delete-authz-binding",
		Short: "Delete an authorization binding for a JWT principal",
		Example: `  certctl delete-authz-binding --id binding-id
  certctl delete-authz-binding --principal 'role:https://sso.example.com/realms/certctl:certctl_admin' --permission doctor.read
  certctl delete-authz-binding --id binding-id --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := resolveAuthzBindingForDelete(store, storage.AuthzBindingFilter{
				ID:           id,
				Principal:    principal,
				Permission:   permission,
				ResourceKind: resourceKind,
				ResourceRef:  resourceRef,
			})
			if err != nil {
				return err
			}
			if err := store.DeleteAuthzBinding(rec.ID); err != nil {
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
	cmd.Flags().StringVar(&principal, "principal", "", "delete by exact principal")
	cmd.Flags().StringVar(&permission, "permission", "", "delete by exact permission")
	cmd.Flags().StringVar(&resourceKind, "resource-kind", "", "delete by exact resource kind")
	cmd.Flags().StringVar(&resourceRef, "resource-ref", "", "delete by exact resource ref")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}

func resolveAuthzBindingForDelete(store *storage.Store, filter storage.AuthzBindingFilter) (storage.AuthzBinding, error) {
	if filter.ID != "" {
		return store.GetAuthzBindingByID(filter.ID)
	}
	if filter.Principal == "" || filter.Permission == "" {
		return storage.AuthzBinding{}, fmt.Errorf("either --id or both --principal and --permission are required")
	}
	rows, err := store.ListAuthzBindingsFiltered(false, filter)
	if err != nil {
		return storage.AuthzBinding{}, err
	}
	switch len(rows) {
	case 0:
		return storage.AuthzBinding{}, fmt.Errorf("authz binding not found")
	case 1:
		return rows[0], nil
	default:
		return storage.AuthzBinding{}, fmt.Errorf("multiple authz bindings matched; add --resource-kind, --resource-ref, or use --id")
	}
}
