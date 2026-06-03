package cmd

import (
	"fmt"
	"strings"

	"uvoo-certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var issuer string
	var force bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "delete-auth-issuer",
		Short: "Delete a trusted JWT/OIDC issuer",
		Example: `  uvoo-certctl delete-auth-issuer --issuer https://sso.example.com/realms/uvoo-certctl
  uvoo-certctl delete-auth-issuer --issuer https://sso.example.com/realms/uvoo-certctl --force
  uvoo-certctl delete-auth-issuer --issuer https://sso.example.com/realms/uvoo-certctl --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := store.GetAuthIssuerByIssuer(issuer)
			if err != nil {
				return err
			}
			bindings, err := store.ListAuthzBindings(false)
			if err != nil {
				return err
			}
			var refs []string
			for _, binding := range bindings {
				if authzBindingReferencesIssuer(binding, issuer) {
					refs = append(refs, binding.ID)
				}
			}
			if len(refs) > 0 {
				if !force {
					return fmt.Errorf("auth issuer %s is still referenced by authz bindings: %s (use --force to delete the bindings and issuer together)", issuer, strings.Join(refs, ", "))
				}
				for _, bindingID := range refs {
					if err := store.DeleteAuthzBinding(bindingID); err != nil {
						return err
					}
					logAuditEvent(store, "delete_authz_binding", "authz_binding", bindingID, fmt.Sprintf("deleted authz binding %s during forced auth issuer deletion", bindingID))
				}
			}

			if err := store.DeleteAuthIssuer(issuer); err != nil {
				return err
			}

			summary := fmt.Sprintf("deleted auth issuer %s", rec.Name)
			if len(refs) > 0 {
				summary = fmt.Sprintf("deleted auth issuer %s and %d referenced authz binding(s)", rec.Name, len(refs))
			}
			logAuditEvent(store, "delete_auth_issuer", "auth_issuer", rec.Issuer, summary)
			if jsonOut {
				payload := authIssuerPayload(rec)
				payload["deleted_binding_ids"] = refs
				payload["forced"] = force
				return printJSON(payload)
			}

			fmt.Printf("Deleted auth issuer %s\n", rec.Name)
			printKV("issuer", rec.Issuer)
			if len(refs) > 0 {
				printKV("deleted_bindings", strings.Join(refs, ", "))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&issuer, "issuer", "", "issuer URL to delete")
	cmd.Flags().BoolVar(&force, "force", false, "delete any authz bindings that reference this issuer before deleting it")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("issuer")
	rootCmd.AddCommand(cmd)
}

func authzBindingReferencesIssuer(binding storage.AuthzBinding, issuer string) bool {
	for _, prefix := range []string{"sub:", "role:", "group:"} {
		if strings.HasPrefix(binding.Principal, prefix+issuer+":") {
			return true
		}
	}
	return false
}
