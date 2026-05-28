package cmd

import (
	"fmt"

	"uvoocertctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var all bool
	var id string
	var principal string
	var permission string
	var resourceKind string
	var resourceRef string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-authz-bindings",
		Short: "List authorization bindings for JWT principals",
		Example: `  uvoocertctl list-authz-bindings
  uvoocertctl list-authz-bindings --principal 'role:https://sso.example.com/realms/uvoocertctl:uvoocertctl_admin'
  uvoocertctl list-authz-bindings --all --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.ListAuthzBindingsFiltered(!all, storage.AuthzBindingFilter{
				ID:           id,
				Principal:    principal,
				Permission:   permission,
				ResourceKind: resourceKind,
				ResourceRef:  resourceRef,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				payload := make([]map[string]any, 0, len(rows))
				for _, row := range rows {
					payload = append(payload, authzBindingPayload(row))
				}
				return printJSON(payload)
			}
			if len(rows) == 0 {
				fmt.Println("No authz bindings found")
				return nil
			}
			for _, row := range rows {
				printKV("id", row.ID)
				printKV("principal", row.Principal)
				printKV("permission", row.Permission)
				printKV("enabled", fmt.Sprintf("%t", row.Enabled))
				if row.ResourceKind != "" {
					printKV("resource_kind", row.ResourceKind)
				}
				if row.ResourceRef != "" {
					printKV("resource_ref", row.ResourceRef)
				}
				fmt.Println()
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "include disabled bindings")
	cmd.Flags().StringVar(&id, "id", "", "filter by binding ID")
	cmd.Flags().StringVar(&principal, "principal", "", "filter by exact principal")
	cmd.Flags().StringVar(&permission, "permission", "", "filter by exact permission")
	cmd.Flags().StringVar(&resourceKind, "resource-kind", "", "filter by exact resource kind")
	cmd.Flags().StringVar(&resourceRef, "resource-ref", "", "filter by exact resource ref")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
