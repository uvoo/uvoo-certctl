package cmd

import (
	"fmt"
	"strings"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var all bool
	var issuer string
	var name string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-subject-auto-approvals",
		Short: "List subject auto-approval rules",
		Example: `  certctl list-subject-auto-approvals
  certctl list-subject-auto-approvals --all --json
  certctl list-subject-auto-approvals --issuer https://accounts.google.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.ListSubjectAutoApprovalRules(!all)
			if err != nil {
				return err
			}

			filtered := make([]storage.SubjectAutoApprovalRule, 0, len(rows))
			for _, row := range rows {
				if issuer != "" && row.Issuer != strings.TrimSpace(issuer) {
					continue
				}
				if name != "" && row.Name != strings.TrimSpace(name) {
					continue
				}
				filtered = append(filtered, row)
			}

			if jsonOut {
				payload := make([]map[string]any, 0, len(filtered))
				for _, row := range filtered {
					payload = append(payload, subjectAutoApprovalRulePayload(row))
				}
				return printJSON(payload)
			}
			if len(filtered) == 0 {
				fmt.Println("No subject auto-approval rules found")
				return nil
			}
			for _, row := range filtered {
				printKV("name", row.Name)
				printKV("issuer", row.Issuer)
				printKV("enabled", fmt.Sprintf("%t", row.Enabled))
				if row.EmailDomain != "" {
					printKV("email_domain", row.EmailDomain)
				}
				if len(row.RequiredRoles) > 0 {
					printKV("required_roles", fmt.Sprintf("%v", row.RequiredRoles))
				}
				if len(row.RequiredGroups) > 0 {
					printKV("required_groups", fmt.Sprintf("%v", row.RequiredGroups))
				}
				if len(row.LocalRoles) > 0 {
					printKV("local_roles", fmt.Sprintf("%v", row.LocalRoles))
				}
				if len(row.LocalGroups) > 0 {
					printKV("local_groups", fmt.Sprintf("%v", row.LocalGroups))
				}
				fmt.Println()
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "include disabled rules")
	cmd.Flags().StringVar(&issuer, "issuer", "", "filter by issuer URL")
	cmd.Flags().StringVar(&name, "name", "", "filter by rule name")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
