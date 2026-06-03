package cmd

import (
	"fmt"
	"sort"

	"uvoo-certctl/internal/auth"
	"uvoo-certctl/internal/storage"
	"uvoo-certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var bearerToken string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "explain-authz",
		Short: "Verify a JWT bearer token and show derived principals and effective permissions",
		Example: `  uvoo-certctl explain-authz --bearer-token env:CERTCTL_BEARER_TOKEN
  uvoo-certctl explain-authz --bearer-token file:/tmp/token.txt --json`,
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
			inspection, err := auth.InspectToken(token)
			if err != nil {
				return err
			}
			matchedIssuer, hasMatchedIssuer := findAuthIssuerByIssuer(issuers, inspection.Issuer)
			verifier := auth.NewVerifier(rootCfg.HTTPTimeout)
			identity, verifyErr := verifier.Verify(cmd.Context(), token, issuers)
			bindings, err := store.ListAuthzBindings(true)
			if err != nil {
				return err
			}
			rules, err := store.ListSubjectAutoApprovalRules(true)
			if err != nil {
				return err
			}

			payload := map[string]any{
				"verified":                            verifyErr == nil,
				"token_issuer":                        emptyStringToNil(inspection.Issuer),
				"token_subject":                       emptyStringToNil(inspection.Subject),
				"token_audiences":                     inspection.Audiences,
				"matched_issuer":                      nil,
				"subject_record":                      nil,
				"subject_status":                      nil,
				"subject_status_reason":               nil,
				"matching_auto_approval_rules":        []string{},
				"matching_auto_approval_local_roles":  []string{},
				"matching_auto_approval_local_groups": []string{},
				"would_be_allowed_now":                false,
				"auth_method":                         nil,
				"issuer":                              nil,
				"subject":                             nil,
				"username":                            nil,
				"email":                               nil,
				"roles":                               []string{},
				"groups":                              []string{},
				"local_roles":                         []string{},
				"local_groups":                        []string{},
				"principals":                          []string{},
				"effective_permissions":               []string{},
				"matching_bindings":                   []map[string]any{},
				"error":                               nil,
			}
			if hasMatchedIssuer {
				payload["matched_issuer"] = authIssuerPayload(matchedIssuer)
				payload["expected_audiences"] = matchedIssuer.Audiences
				payload["required_claims"] = matchedIssuer.RequiredClaims
			} else {
				payload["expected_audiences"] = []string{}
				payload["required_claims"] = map[string]string{}
			}

			if verifyErr == nil {
				var subjectRecPtr *storage.Subject
				if subjectRec, err := store.GetSubject(identity.Issuer, identity.Subject); err == nil {
					payload["subject_record"] = subjectPayload(subjectRec)
					subjectRecCopy := subjectRec
					subjectRecPtr = &subjectRecCopy
				}
				preview := auth.PreviewSubjectAccess(identity, subjectRecPtr, rules)
				identity = preview.Identity
				effectivePermissions := auth.EffectivePermissions(identity, bindings)
				matching := make([]map[string]any, 0, len(bindings))
				for _, permission := range effectivePermissions {
					req := auth.PermissionRequest{Permission: permission}
					for _, binding := range auth.MatchingBindings(identity, bindings, req) {
						matching = append(matching, authzBindingPayload(binding))
					}
				}
				payload["auth_method"] = identity.AuthMethod
				payload["issuer"] = identity.Issuer
				payload["subject"] = identity.Subject
				payload["username"] = emptyStringToNil(identity.Username)
				payload["email"] = emptyStringToNil(identity.Email)
				payload["roles"] = identity.Roles
				payload["groups"] = identity.Groups
				payload["local_roles"] = identity.LocalRoles
				payload["local_groups"] = identity.LocalGroups
				payload["subject_status"] = preview.Status
				payload["subject_status_reason"] = preview.Reason
				payload["matching_auto_approval_rules"] = preview.MatchedRuleNames
				payload["matching_auto_approval_local_roles"] = preview.MatchedLocalRoles
				payload["matching_auto_approval_local_groups"] = preview.MatchedLocalGroups
				payload["would_be_allowed_now"] = preview.Status == storage.SubjectStatusActive
				payload["principals"] = identity.Principals
				payload["effective_permissions"] = effectivePermissions
				payload["matching_bindings"] = matching
			} else {
				payload["error"] = verifyErr.Error()
			}

			if jsonOut {
				return printJSON(payload)
			}

			printKV("verified", fmt.Sprintf("%t", verifyErr == nil))
			if inspection.Issuer != "" {
				printKV("token_issuer", inspection.Issuer)
			}
			if len(inspection.Audiences) > 0 {
				printStringList("token_audiences", inspection.Audiences)
			}
			if hasMatchedIssuer {
				printKV("matched_issuer", matchedIssuer.Issuer)
				if len(matchedIssuer.Audiences) > 0 {
					printStringList("expected_audiences", matchedIssuer.Audiences)
				}
				if len(matchedIssuer.RequiredClaims) > 0 {
					printKV("required_claims", fmt.Sprintf("%v", matchedIssuer.RequiredClaims))
				}
			}
			if verifyErr != nil {
				printKV("error", verifyErr.Error())
				return nil
			}
			if payload["subject_status"] != nil {
				printKV("subject_status", fmt.Sprintf("%v", payload["subject_status"]))
			}
			if payload["subject_status_reason"] != nil {
				printKV("subject_status_reason", fmt.Sprintf("%v", payload["subject_status_reason"]))
			}
			if rules, ok := payload["matching_auto_approval_rules"].([]string); ok {
				printStringList("matching_auto_approval_rules", rules)
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
			printStringList("local_roles", identity.LocalRoles)
			printStringList("local_groups", identity.LocalGroups)
			printStringList("principals", identity.Principals)
			printKV("would_be_allowed_now", fmt.Sprintf("%t", payload["would_be_allowed_now"].(bool)))
			printStringList("effective_permissions", auth.EffectivePermissions(identity, bindings))
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

func findAuthIssuerByIssuer(issuers []storage.AuthIssuer, issuer string) (storage.AuthIssuer, bool) {
	for _, candidate := range issuers {
		if candidate.Issuer == issuer {
			return candidate, true
		}
	}
	return storage.AuthIssuer{}, false
}
