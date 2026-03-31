package cmd

import (
	"fmt"
	"strings"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var name string
	var issuer string
	var audiences []string
	var discoveryURL string
	var jwksURL string
	var enabled bool
	var subjectClaim string
	var usernameClaim string
	var emailClaim string
	var rolesClaims []string
	var groupsClaims []string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "update-auth-issuer",
		Short: "Update a trusted JWT/OIDC issuer",
		Example: `  certctl update-auth-issuer \
    --issuer https://sso.example.com/realms/certctl \
    --name keycloak-prod \
    --audience certctl
  certctl update-auth-issuer \
    --issuer https://sso.example.com/realms/certctl \
    --enabled=false --json`,
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

			flags := cmd.Flags()
			if flags.Changed("name") {
				rec.Name = name
			}
			if flags.Changed("audience") {
				rec.Audiences = compactStrings(audiences)
			}
			if flags.Changed("discovery-url") {
				rec.DiscoveryURL = strings.TrimSpace(discoveryURL)
			}
			if flags.Changed("jwks-url") {
				rec.JWKSURL = strings.TrimSpace(jwksURL)
			}
			if flags.Changed("enabled") {
				rec.Enabled = enabled
			}
			if flags.Changed("subject-claim") {
				rec.SubjectClaim = strings.TrimSpace(subjectClaim)
			}
			if flags.Changed("username-claim") {
				rec.UsernameClaim = strings.TrimSpace(usernameClaim)
			}
			if flags.Changed("email-claim") {
				rec.EmailClaim = strings.TrimSpace(emailClaim)
			}
			if flags.Changed("roles-claim") {
				rec.RolesClaims = compactStrings(rolesClaims)
			}
			if flags.Changed("groups-claim") {
				rec.GroupsClaims = compactStrings(groupsClaims)
			}

			if err := store.UpsertAuthIssuer(rec); err != nil {
				return err
			}
			rec, err = store.GetAuthIssuerByIssuer(issuer)
			if err != nil {
				return err
			}

			logAuditEvent(store, "update_auth_issuer", "auth_issuer", rec.Issuer, fmt.Sprintf("updated auth issuer %s", rec.Name))
			if jsonOut {
				return printJSON(authIssuerPayload(rec))
			}

			fmt.Printf("Updated auth issuer %s\n", rec.Name)
			printKV("issuer", rec.Issuer)
			printKV("enabled", fmt.Sprintf("%t", rec.Enabled))
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "logical name for the trusted issuer")
	cmd.Flags().StringVar(&issuer, "issuer", "", "issuer URL to update")
	cmd.Flags().StringSliceVar(&audiences, "audience", nil, "expected JWT audience; repeat as needed")
	cmd.Flags().StringVar(&discoveryURL, "discovery-url", "", "OIDC discovery URL; pass an empty value to clear")
	cmd.Flags().StringVar(&jwksURL, "jwks-url", "", "JWKS URL override; pass an empty value to clear")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "whether this issuer is enabled")
	cmd.Flags().StringVar(&subjectClaim, "subject-claim", "", "claim path used as the canonical subject")
	cmd.Flags().StringVar(&usernameClaim, "username-claim", "", "claim path used as the display username")
	cmd.Flags().StringVar(&emailClaim, "email-claim", "", "claim path used as the email")
	cmd.Flags().StringSliceVar(&rolesClaims, "roles-claim", nil, "claim path used for roles; repeat as needed")
	cmd.Flags().StringSliceVar(&groupsClaims, "groups-claim", nil, "claim path used for groups; repeat as needed")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("issuer")
	rootCmd.AddCommand(cmd)
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if v := strings.TrimSpace(value); v != "" {
			out = append(out, v)
		}
	}
	return out
}
