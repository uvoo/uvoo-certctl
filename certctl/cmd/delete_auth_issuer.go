package cmd

import (
	"fmt"
	"strings"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var issuer string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "delete-auth-issuer",
		Short: "Delete a trusted JWT/OIDC issuer",
		Example: `  certctl delete-auth-issuer --issuer https://sso.example.com/realms/certctl
  certctl delete-auth-issuer --issuer https://sso.example.com/realms/certctl --json`,
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
				return fmt.Errorf("auth issuer %s is still referenced by authz bindings: %s", issuer, strings.Join(refs, ", "))
			}

			if err := store.DeleteAuthIssuer(issuer); err != nil {
				return err
			}

			logAuditEvent(store, "delete_auth_issuer", "auth_issuer", rec.Issuer, fmt.Sprintf("deleted auth issuer %s", rec.Name))
			if jsonOut {
				return printJSON(authIssuerPayload(rec))
			}

			fmt.Printf("Deleted auth issuer %s\n", rec.Name)
			printKV("issuer", rec.Issuer)
			return nil
		},
	}

	cmd.Flags().StringVar(&issuer, "issuer", "", "issuer URL to delete")
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
