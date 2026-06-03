package cmd

import (
	"fmt"

	"uvoo-certctl/internal/storage"
	"uvoo-certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var name string
	var issuer string
	var emailDomain string
	var requiredRoles []string
	var requiredGroups []string
	var localRoles []string
	var localGroups []string
	var enabled bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "create-subject-auto-approval",
		Short: "Create or update a subject auto-approval rule",
		Example: `  uvoo-certctl create-subject-auto-approval \
    --name google-employees \
    --issuer https://accounts.google.com \
    --email-domain example.com \
    --local-group employees
  uvoo-certctl create-subject-auto-approval \
    --name keycloak-admins \
    --issuer https://sso.example.com/realms/uvoo-certctl \
    --required-role uvoo-certctl_admin \
    --local-role admin --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if err := store.UpsertSubjectAutoApprovalRule(storage.SubjectAutoApprovalRule{
				ID:             util.NewID(),
				Name:           name,
				Enabled:        enabled,
				Issuer:         issuer,
				EmailDomain:    emailDomain,
				RequiredRoles:  compactStrings(requiredRoles),
				RequiredGroups: compactStrings(requiredGroups),
				LocalRoles:     compactStrings(localRoles),
				LocalGroups:    compactStrings(localGroups),
			}); err != nil {
				return err
			}

			rec, err := store.GetSubjectAutoApprovalRuleByName(name)
			if err != nil {
				return err
			}
			logAuditEvent(store, "upsert_subject_auto_approval", "subject_auto_approval_rule", rec.Name, rec.Issuer)

			if jsonOut {
				return printJSON(subjectAutoApprovalRulePayload(rec))
			}
			fmt.Printf("Configured subject auto approval %s\n", rec.Name)
			printKV("issuer", rec.Issuer)
			printKV("enabled", fmt.Sprintf("%t", rec.Enabled))
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "logical name for the subject auto-approval rule")
	cmd.Flags().StringVar(&issuer, "issuer", "", "issuer URL the rule applies to")
	cmd.Flags().StringVar(&emailDomain, "email-domain", "", "optional email domain match, for example example.com")
	cmd.Flags().StringSliceVar(&requiredRoles, "required-role", nil, "required upstream role; repeat as needed")
	cmd.Flags().StringSliceVar(&requiredGroups, "required-group", nil, "required upstream group; repeat as needed")
	cmd.Flags().StringSliceVar(&localRoles, "local-role", nil, "local role to assign on auto-approval; repeat as needed")
	cmd.Flags().StringSliceVar(&localGroups, "local-group", nil, "local group to assign on auto-approval; repeat as needed")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "whether the rule is enabled")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("issuer")
	rootCmd.AddCommand(cmd)
}
