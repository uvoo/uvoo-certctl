package cmd

import (
	"fmt"
	"sort"

	"certctl/internal/auth"
	"certctl/internal/storage"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var bearerToken string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "explain-authz",
		Short: "Verify a JWT bearer token and show derived principals and effective permissions",
		Example: `  certctl explain-authz --bearer-token env:CERTCTL_BEARER_TOKEN
  certctl explain-authz --bearer-token file:/tmp/token.txt --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := util.ResolveSecretValue(bearerToken, "CERTCTL_BEARER_TOKEN")
			if err != nil {
				return err
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			issuers, err := store.ListAuthIssuers(true)
			if err != nil {
				return err
			}
			verifier := auth.NewVerifier(rootCfg.HTTPTimeout)
			identity, err := verifier.Verify(cmd.Context(), token, issuers)
			if err != nil {
				return err
			}

			bindings, err := store.ListAuthzBindings(true)
			if err != nil {
				return err
			}

			effectivePermissions := auth.EffectivePermissions(identity, bindings)
			matching := make([]map[string]any, 0, len(bindings))
			for _, permission := range effectivePermissions {
				req := auth.PermissionRequest{Permission: permission}
				for _, binding := range auth.MatchingBindings(identity, bindings, req) {
					matching = append(matching, authzBindingPayload(binding))
				}
			}

			payload := map[string]any{
				"auth_method":           identity.AuthMethod,
				"issuer":                identity.Issuer,
				"subject":               identity.Subject,
				"username":              emptyStringToNil(identity.Username),
				"email":                 emptyStringToNil(identity.Email),
				"roles":                 identity.Roles,
				"groups":                identity.Groups,
				"principals":            identity.Principals,
				"effective_permissions": effectivePermissions,
				"matching_bindings":     matching,
			}

			if jsonOut {
				return printJSON(payload)
			}

			printKV("auth_method", identity.AuthMethod)
			printKV("issuer", identity.Issuer)
			printKV("subject", identity.Subject)
			if identity.Username != "" {
				printKV("username", identity.Username)
			}
			if identity.Email != "" {
				printKV("email", identity.Email)
			}
			printStringList("roles", identity.Roles)
			printStringList("groups", identity.Groups)
			printStringList("principals", identity.Principals)
			printStringList("effective_permissions", effectivePermissions)
			return nil
		},
	}

	cmd.Flags().StringVar(&bearerToken, "bearer-token", "", "bearer token value, env:VAR, or file:/path")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("bearer-token")
	rootCmd.AddCommand(cmd)
}

func printStringList(label string, values []string) {
	if len(values) == 0 {
		return
	}
	copied := append([]string(nil), values...)
	sort.Strings(copied)
	printKV(label, fmt.Sprintf("%v", copied))
}
