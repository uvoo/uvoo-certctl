package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var all bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-authz-bindings",
		Short: "List authorization bindings for JWT principals",
		Example: `  certctl list-authz-bindings
  certctl list-authz-bindings --all --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.ListAuthzBindings(!all)
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
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
