package cmd

import (
	"fmt"

	"uvoocertctl/internal/auth"
	"github.com/spf13/cobra"
)

func init() {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-auth-provider-presets",
		Short: "List built-in JWT/OIDC issuer presets",
		Example: `  uvoocertctl list-auth-provider-presets
  uvoocertctl list-auth-provider-presets --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			names := auth.ProviderPresetNames()
			if jsonOut {
				payload := make([]map[string]any, 0, len(names))
				for _, name := range names {
					rec, _ := auth.ProviderPresetByName(name)
					payload = append(payload, authProviderPresetPayload(rec))
				}
				return printJSON(payload)
			}
			for _, name := range names {
				rec, _ := auth.ProviderPresetByName(name)
				printKV("preset", name)
				if rec.Description != "" {
					printKV("description", rec.Description)
				}
				printKV("issuer", rec.Issuer)
				printKV("discovery_url", rec.DiscoveryURL)
				if rec.Issuer == "" {
					printKV("requires_issuer", "true")
				}
				fmt.Println()
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}

func authProviderPresetPayload(rec auth.ProviderPreset) map[string]any {
	return map[string]any{
		"name":            rec.Name,
		"description":     emptyStringToNil(rec.Description),
		"issuer":          rec.Issuer,
		"discovery_url":   rec.DiscoveryURL,
		"requires_issuer": rec.Issuer == "",
		"subject_claim":   rec.SubjectClaim,
		"username_claim":  rec.UsernameClaim,
		"email_claim":     rec.EmailClaim,
		"roles_claims":    rec.RolesClaims,
		"groups_claims":   rec.GroupsClaims,
	}
}
