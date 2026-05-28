package cmd

import (
	"fmt"

	"certctl/internal/auth"
	"certctl/internal/storage"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var principals []string
	var bearerToken string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-effective-authz",
		Short: "List effective permissions and matching bindings for principals or a bearer token",
		Example: `  certctl list-effective-authz --principal 'role:https://sso.example.com/realms/certctl:certctl_admin'
  certctl list-effective-authz --principal 'role:https://sso.example.com/realms/certctl:certctl_admin' --principal 'group:https://sso.example.com/realms/certctl:platform'
  certctl list-effective-authz --bearer-token env:CERTCTL_BEARER_TOKEN --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(principals) == 0 && bearerToken == "" {
				return fmt.Errorf("either --principal or --bearer-token is required")
			}
			if len(principals) > 0 && bearerToken != "" {
				return fmt.Errorf("--principal and --bearer-token are mutually exclusive")
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			bindings, err := store.ListAuthzBindings(true)
			if err != nil {
				return err
			}

			mode := "principals"
			identity := auth.Identity{
				AuthMethod: "local",
				Principals: compactStrings(principals),
			}
			var matchedIssuer any
			var subjectRecord any
			var subjectStatus any
			var subjectStatusReason any
			var matchingAutoApprovalRules []string
			if bearerToken != "" {
				mode = "bearer_token"
				token, err := util.ResolveSecretValue(bearerToken, "CERTCTL_BEARER_TOKEN")
				if err != nil {
					return err
				}
				issuers, err := store.ListAuthIssuers(true)
				if err != nil {
					return err
				}
				inspection, err := auth.InspectToken(token)
				if err != nil {
					return err
				}
				if issuer, ok := findAuthIssuerByIssuer(issuers, inspection.Issuer); ok {
					matchedIssuer = authIssuerPayload(issuer)
				}
				verifier := auth.NewVerifier(rootCfg.HTTPTimeout)
				identity, err = verifier.Verify(cmd.Context(), token, issuers)
				if err != nil {
					return err
				}
				rules, err := store.ListSubjectAutoApprovalRules(true)
				if err != nil {
					return err
				}
				var subjectRecPtr *storage.Subject
				if subjectRec, err := store.GetSubject(identity.Issuer, identity.Subject); err == nil {
					subjectRecord = subjectPayload(subjectRec)
					subjectRecCopy := subjectRec
					subjectRecPtr = &subjectRecCopy
				}
				preview := auth.PreviewSubjectAccess(identity, subjectRecPtr, rules)
				identity = preview.Identity
				subjectStatus = preview.Status
				subjectStatusReason = preview.Reason
				matchingAutoApprovalRules = preview.MatchedRuleNames
			}

			effectivePermissions := auth.EffectivePermissions(identity, bindings)
			matchingBindings := collectMatchingBindings(identity, bindings, effectivePermissions)
			payload := map[string]any{
				"input_mode":                   mode,
				"matched_issuer":               matchedIssuer,
				"subject_record":               subjectRecord,
				"subject_status":               subjectStatus,
				"subject_status_reason":        subjectStatusReason,
				"matching_auto_approval_rules": matchingAutoApprovalRules,
				"principals":                   identity.Principals,
				"roles":                        identity.Roles,
				"groups":                       identity.Groups,
				"local_roles":                  identity.LocalRoles,
				"local_groups":                 identity.LocalGroups,
				"effective_permissions":        effectivePermissions,
				"matching_bindings":            matchingBindings,
			}

			if jsonOut {
				return printJSON(payload)
			}

			printKV("input_mode", mode)
			if matchedIssuer != nil {
				printKV("matched_issuer", fmt.Sprintf("%v", matchedIssuer.(map[string]any)["issuer"]))
			}
			if subjectStatus != nil {
				printKV("subject_status", fmt.Sprintf("%v", subjectStatus))
			}
			if subjectStatusReason != nil {
				printKV("subject_status_reason", fmt.Sprintf("%v", subjectStatusReason))
			}
			printStringList("matching_auto_approval_rules", matchingAutoApprovalRules)
			printStringList("principals", identity.Principals)
			printStringList("roles", identity.Roles)
			printStringList("groups", identity.Groups)
			printStringList("local_roles", identity.LocalRoles)
			printStringList("local_groups", identity.LocalGroups)
			printStringList("effective_permissions", effectivePermissions)
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&principals, "principal", nil, "principal string such as sub:<issuer>:<sub> or role:<issuer>:<role>; repeat as needed")
	cmd.Flags().StringVar(&bearerToken, "bearer-token", "", "bearer token value, env:VAR, or file:/path")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}

func collectMatchingBindings(identity auth.Identity, bindings []storage.AuthzBinding, permissions []string) []map[string]any {
	seen := map[string]struct{}{}
	var out []map[string]any
	for _, permission := range permissions {
		req := auth.PermissionRequest{Permission: permission}
		for _, binding := range auth.MatchingBindings(identity, bindings, req) {
			if _, ok := seen[binding.ID]; ok {
				continue
			}
			seen[binding.ID] = struct{}{}
			out = append(out, authzBindingPayload(binding))
		}
	}
	return out
}
