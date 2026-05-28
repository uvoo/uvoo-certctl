package cmd

import (
	"fmt"
	"strings"

	"uvoocertctl/internal/auth"
	"uvoocertctl/internal/storage"
	"uvoocertctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var name string
	var preset string
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
	var requiredClaims []string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "create-auth-issuer",
		Short: "Create or update a trusted JWT/OIDC issuer",
		Example: `  uvoocertctl create-auth-issuer \
    --name keycloak-local \
    --issuer https://sso.example.com/realms/uvoocertctl \
    --audience uvoocertctl \
    --discovery-url https://sso.example.com/realms/uvoocertctl/.well-known/openid-configuration \
    --roles-claim realm_access.roles
  uvoocertctl create-auth-issuer --preset google --name google-login --audience <client-id>
  uvoocertctl create-auth-issuer --preset keycloak --name keycloak-local --issuer https://sso.example.com/realms/uvoocertctl --audience uvoocertctl
  uvoocertctl create-auth-issuer --preset aws-cognito --name cognito-dev --issuer https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example --audience <app-client-id>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if preset != "" {
				rec, ok := auth.ProviderPresetByName(strings.TrimSpace(preset))
				if !ok {
					return fmt.Errorf("unknown auth provider preset %q", preset)
				}
				if name == "" {
					name = rec.Name
				}
				if issuer == "" {
					issuer = rec.Issuer
				}
				if discoveryURL == "" {
					discoveryURL = rec.DiscoveryURL
				}
				if subjectClaim == "sub" {
					subjectClaim = rec.SubjectClaim
				}
				if usernameClaim == "preferred_username" {
					usernameClaim = rec.UsernameClaim
				}
				if emailClaim == "email" {
					emailClaim = rec.EmailClaim
				}
				if len(rolesClaims) == 2 && rolesClaims[0] == "roles" && rolesClaims[1] == "realm_access.roles" {
					rolesClaims = rec.RolesClaims
				}
				if len(groupsClaims) == 1 && groupsClaims[0] == "groups" {
					groupsClaims = rec.GroupsClaims
				}
				if len(audiences) == 0 {
					return fmt.Errorf("--audience is required when using --preset %s", preset)
				}
			}
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("--name is required")
			}
			if strings.TrimSpace(issuer) == "" {
				return fmt.Errorf("--issuer is required")
			}
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if err := store.UpsertAuthIssuer(storage.AuthIssuer{
				ID:             util.NewID(),
				Name:           name,
				Enabled:        enabled,
				Issuer:         issuer,
				Audiences:      audiences,
				RequiredClaims: parseRequiredClaims(requiredClaims),
				DiscoveryURL:   discoveryURL,
				JWKSURL:        jwksURL,
				SubjectClaim:   subjectClaim,
				UsernameClaim:  usernameClaim,
				EmailClaim:     emailClaim,
				RolesClaims:    rolesClaims,
				GroupsClaims:   groupsClaims,
			}); err != nil {
				return err
			}

			rec, err := store.GetAuthIssuerByIssuer(issuer)
			if err != nil {
				return err
			}

			if jsonOut {
				return printJSON(authIssuerPayload(rec))
			}

			fmt.Printf("Configured auth issuer %s\n", rec.Name)
			printKV("issuer", rec.Issuer)
			printKV("enabled", fmt.Sprintf("%t", rec.Enabled))
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "logical name for the trusted issuer")
	cmd.Flags().StringVar(&preset, "preset", "", "built-in auth provider preset, for example google or microsoft-consumers")
	cmd.Flags().StringVar(&issuer, "issuer", "", "expected JWT iss claim")
	cmd.Flags().StringSliceVar(&audiences, "audience", nil, "expected JWT audience; repeat as needed")
	cmd.Flags().StringVar(&discoveryURL, "discovery-url", "", "optional OIDC discovery URL; defaults from issuer when omitted")
	cmd.Flags().StringVar(&jwksURL, "jwks-url", "", "optional JWKS URL override")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "whether this issuer is enabled")
	cmd.Flags().StringVar(&subjectClaim, "subject-claim", "sub", "claim path used as the canonical subject")
	cmd.Flags().StringVar(&usernameClaim, "username-claim", "preferred_username", "claim path used as the display username")
	cmd.Flags().StringVar(&emailClaim, "email-claim", "email", "claim path used as the email")
	cmd.Flags().StringSliceVar(&rolesClaims, "roles-claim", []string{"roles", "realm_access.roles"}, "claim path used for roles; repeat as needed")
	cmd.Flags().StringSliceVar(&groupsClaims, "groups-claim", []string{"groups"}, "claim path used for groups; repeat as needed")
	cmd.Flags().StringSliceVar(&requiredClaims, "required-claim", nil, "required claim match in path=value form; repeat as needed")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}

func authIssuerPayload(rec storage.AuthIssuer) map[string]any {
	return map[string]any{
		"id":              rec.ID,
		"name":            rec.Name,
		"enabled":         rec.Enabled,
		"issuer":          rec.Issuer,
		"audiences":       rec.Audiences,
		"required_claims": rec.RequiredClaims,
		"discovery_url":   emptyStringToNil(rec.DiscoveryURL),
		"jwks_url":        emptyStringToNil(rec.JWKSURL),
		"subject_claim":   rec.SubjectClaim,
		"username_claim":  rec.UsernameClaim,
		"email_claim":     rec.EmailClaim,
		"roles_claims":    rec.RolesClaims,
		"groups_claims":   rec.GroupsClaims,
		"created_at":      formatTimeValue(rec.CreatedAt),
		"updated_at":      formatTimeValue(rec.UpdatedAt),
	}
}

func parseRequiredClaims(values []string) map[string]string {
	out := map[string]string{}
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		key, value, ok := strings.Cut(raw, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
