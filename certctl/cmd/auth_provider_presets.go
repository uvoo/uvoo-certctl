package cmd

import (
	"fmt"
	"sort"
)

type authProviderPreset struct {
	Name          string
	Description   string
	Issuer        string
	DiscoveryURL  string
	SubjectClaim  string
	UsernameClaim string
	EmailClaim    string
	RolesClaims   []string
	GroupsClaims  []string
}

var authProviderPresets = map[string]authProviderPreset{
	"google": {
		Name:          "google",
		Description:   "Google Accounts and Google Workspace OIDC",
		Issuer:        "https://accounts.google.com",
		DiscoveryURL:  "https://accounts.google.com/.well-known/openid-configuration",
		SubjectClaim:  "sub",
		UsernameClaim: "email",
		EmailClaim:    "email",
		RolesClaims:   []string{"roles"},
		GroupsClaims:  []string{"groups"},
	},
	"microsoft-common": {
		Name:          "microsoft-common",
		Description:   "Microsoft Entra tenant-independent common endpoint",
		Issuer:        "https://login.microsoftonline.com/common/v2.0",
		DiscoveryURL:  "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
		SubjectClaim:  "sub",
		UsernameClaim: "preferred_username",
		EmailClaim:    "email",
		RolesClaims:   []string{"roles"},
		GroupsClaims:  []string{"groups"},
	},
	"microsoft-consumers": {
		Name:          "microsoft-consumers",
		Description:   "Microsoft personal accounts only",
		Issuer:        "https://login.microsoftonline.com/consumers/v2.0",
		DiscoveryURL:  "https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration",
		SubjectClaim:  "sub",
		UsernameClaim: "preferred_username",
		EmailClaim:    "email",
		RolesClaims:   []string{"roles"},
		GroupsClaims:  []string{"groups"},
	},
	"microsoft-tenant": {
		Name:          "microsoft-tenant",
		Description:   "Microsoft Entra tenant-specific issuer; pass --issuer for your tenant",
		SubjectClaim:  "sub",
		UsernameClaim: "preferred_username",
		EmailClaim:    "email",
		RolesClaims:   []string{"roles"},
		GroupsClaims:  []string{"groups"},
	},
	"keycloak": {
		Name:          "keycloak",
		Description:   "Generic Keycloak realm issuer; pass --issuer for your realm",
		SubjectClaim:  "sub",
		UsernameClaim: "preferred_username",
		EmailClaim:    "email",
		RolesClaims:   []string{"realm_access.roles"},
		GroupsClaims:  []string{"groups"},
	},
	"aws-cognito": {
		Name:          "aws-cognito",
		Description:   "Amazon Cognito user pool issuer; pass --issuer for your user pool",
		SubjectClaim:  "sub",
		UsernameClaim: "cognito:username",
		EmailClaim:    "email",
		RolesClaims:   []string{},
		GroupsClaims:  []string{"cognito:groups", "groups"},
	},
}

func authProviderPresetByName(name string) (authProviderPreset, bool) {
	rec, ok := authProviderPresets[name]
	return rec, ok
}

func authProviderPresetNames() []string {
	out := make([]string, 0, len(authProviderPresets))
	for name := range authProviderPresets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func authProviderPresetSummary(name string, rec authProviderPreset) string {
	return fmt.Sprintf("%s (%s)", name, rec.Issuer)
}
