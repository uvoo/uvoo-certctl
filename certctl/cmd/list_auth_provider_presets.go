package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-auth-provider-presets",
		Short: "List built-in JWT/OIDC issuer presets",
		Example: `  certctl list-auth-provider-presets
  certctl list-auth-provider-presets --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			names := authProviderPresetNames()
			if jsonOut {
				payload := make([]map[string]any, 0, len(names))
				for _, name := range names {
					rec := authProviderPresets[name]
					payload = append(payload, map[string]any{
						"name":           name,
						"issuer":         rec.Issuer,
						"discovery_url":  rec.DiscoveryURL,
						"subject_claim":  rec.SubjectClaim,
						"username_claim": rec.UsernameClaim,
						"email_claim":    rec.EmailClaim,
						"roles_claims":   rec.RolesClaims,
						"groups_claims":  rec.GroupsClaims,
					})
				}
				return printJSON(payload)
			}
			for _, name := range names {
				rec := authProviderPresets[name]
				printKV("preset", name)
				printKV("issuer", rec.Issuer)
				printKV("discovery_url", rec.DiscoveryURL)
				fmt.Println()
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
