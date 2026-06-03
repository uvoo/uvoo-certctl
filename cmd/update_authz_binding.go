package cmd

import (
	"fmt"
	"strings"

	"uvoo-certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var id string
	var matchPrincipal string
	var matchPermission string
	var matchResourceKind string
	var matchResourceRef string
	var principal string
	var permission string
	var resourceKind string
	var resourceRef string
	var enabled bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "update-authz-binding",
		Short: "Update an authorization binding for a JWT principal",
		Example: `  uvoo-certctl update-authz-binding \
    --id binding-id \
    --permission csr.approve
  uvoo-certctl update-authz-binding \
    --match-principal 'role:https://sso.example.com/realms/uvoo-certctl:uvoo-certctl_admin' \
    --match-permission doctor.read \
    --permission metrics.read
  uvoo-certctl update-authz-binding \
    --id binding-id \
    --enabled=false --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := resolveAuthzBinding(store, storage.AuthzBindingFilter{
				ID:           id,
				Principal:    matchPrincipal,
				Permission:   matchPermission,
				ResourceKind: matchResourceKind,
				ResourceRef:  matchResourceRef,
			})
			if err != nil {
				return err
			}

			flags := cmd.Flags()
			if flags.Changed("principal") {
				rec.Principal = strings.TrimSpace(principal)
			}
			if flags.Changed("permission") {
				rec.Permission = strings.TrimSpace(permission)
			}
			if flags.Changed("resource-kind") {
				rec.ResourceKind = strings.TrimSpace(resourceKind)
			}
			if flags.Changed("resource-ref") {
				rec.ResourceRef = strings.TrimSpace(resourceRef)
			}
			if flags.Changed("enabled") {
				rec.Enabled = enabled
			}

			if err := store.UpdateAuthzBinding(rec); err != nil {
				return err
			}
			rec, err = store.GetAuthzBindingByID(rec.ID)
			if err != nil {
				return err
			}

			logAuditEvent(store, "update_authz_binding", "authz_binding", rec.ID, fmt.Sprintf("updated authz binding %s", rec.ID))
			if jsonOut {
				return printJSON(authzBindingPayload(rec))
			}

			fmt.Printf("Updated authz binding %s\n", rec.ID)
			printKV("principal", rec.Principal)
			printKV("permission", rec.Permission)
			return nil
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "binding ID to update")
	cmd.Flags().StringVar(&matchPrincipal, "match-principal", "", "match by exact principal when --id is not used")
	cmd.Flags().StringVar(&matchPermission, "match-permission", "", "match by exact permission when --id is not used")
	cmd.Flags().StringVar(&matchResourceKind, "match-resource-kind", "", "match by exact resource kind when --id is not used")
	cmd.Flags().StringVar(&matchResourceRef, "match-resource-ref", "", "match by exact resource ref when --id is not used")
	cmd.Flags().StringVar(&principal, "principal", "", "principal string such as sub:<issuer>:<sub> or role:<issuer>:<role>")
	cmd.Flags().StringVar(&permission, "permission", "", "permission name such as doctor.read or csr.approve")
	cmd.Flags().StringVar(&resourceKind, "resource-kind", "", "optional scoped resource kind; pass an empty value to clear")
	cmd.Flags().StringVar(&resourceRef, "resource-ref", "", "optional scoped resource reference; pass an empty value to clear")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "whether this binding is enabled")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
