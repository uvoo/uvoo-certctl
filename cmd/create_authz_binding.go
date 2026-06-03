package cmd

import (
	"fmt"

	"uvoo-certctl/internal/storage"
	"uvoo-certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var principal string
	var permission string
	var resourceKind string
	var resourceRef string
	var enabled bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "create-authz-binding",
		Short: "Create an authorization binding for a JWT principal",
		Example: `  uvoo-certctl create-authz-binding \
    --principal 'role:https://sso.example.com/realms/uvoo-certctl:uvoo-certctl_admin' \
    --permission csr.approve \
    --resource-kind csr_request \
    --resource-ref '*'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec := storage.AuthzBinding{
				ID:           util.NewID(),
				Enabled:      enabled,
				Principal:    principal,
				Permission:   permission,
				ResourceKind: resourceKind,
				ResourceRef:  resourceRef,
			}
			if err := store.CreateAuthzBinding(rec); err != nil {
				return err
			}

			if jsonOut {
				return printJSON(authzBindingPayload(rec))
			}

			fmt.Printf("Created authz binding %s\n", rec.ID)
			printKV("principal", rec.Principal)
			printKV("permission", rec.Permission)
			return nil
		},
	}

	cmd.Flags().StringVar(&principal, "principal", "", "principal string such as sub:<issuer>:<sub> or role:<issuer>:<role>")
	cmd.Flags().StringVar(&permission, "permission", "", "permission name such as doctor.read or csr.approve")
	cmd.Flags().StringVar(&resourceKind, "resource-kind", "", "optional scoped resource kind")
	cmd.Flags().StringVar(&resourceRef, "resource-ref", "", "optional scoped resource reference; use * for any resource of the kind")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "whether this binding is enabled")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("principal")
	_ = cmd.MarkFlagRequired("permission")
	rootCmd.AddCommand(cmd)
}

func authzBindingPayload(rec storage.AuthzBinding) map[string]any {
	return map[string]any{
		"id":            rec.ID,
		"enabled":       rec.Enabled,
		"principal":     rec.Principal,
		"permission":    rec.Permission,
		"resource_kind": emptyStringToNil(rec.ResourceKind),
		"resource_ref":  emptyStringToNil(rec.ResourceRef),
		"created_at":    formatTimeValue(rec.CreatedAt),
		"updated_at":    formatTimeValue(rec.UpdatedAt),
	}
}
