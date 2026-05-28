package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var issuer string
	var subject string
	var localRoles []string
	var localGroups []string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "approve-subject",
		Short: "Approve a pending JWT subject and optionally assign local roles or groups",
		Example: `  certctl approve-subject --issuer https://accounts.google.com --subject user-123
  certctl approve-subject --issuer https://accounts.google.com --subject user-123 --local-group viewers
  certctl approve-subject --issuer https://accounts.google.com --subject user-123 --local-role admin --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := store.GetSubject(issuer, subject)
			if err != nil {
				return err
			}

			roles := rec.LocalRoles
			groups := rec.LocalGroups
			if cmd.Flags().Changed("local-role") {
				roles = compactStrings(localRoles)
			}
			if cmd.Flags().Changed("local-group") {
				groups = compactStrings(localGroups)
			}

			if err := store.UpdateSubjectApproval(issuer, subject, storage.SubjectStatusActive, roles, groups); err != nil {
				return err
			}
			rec, err = store.GetSubject(issuer, subject)
			if err != nil {
				return err
			}
			logAuditEvent(store, "approve_subject", "subject", rec.ID, rec.Issuer+" "+rec.Subject)

			if jsonOut {
				return printJSON(subjectPayload(rec))
			}
			fmt.Printf("Approved subject %s\n", rec.Subject)
			printKV("issuer", rec.Issuer)
			if len(rec.LocalRoles) > 0 {
				printKV("local_roles", fmt.Sprintf("%v", rec.LocalRoles))
			}
			if len(rec.LocalGroups) > 0 {
				printKV("local_groups", fmt.Sprintf("%v", rec.LocalGroups))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&issuer, "issuer", "", "issuer URL for the subject")
	cmd.Flags().StringVar(&subject, "subject", "", "subject value to approve")
	cmd.Flags().StringSliceVar(&localRoles, "local-role", nil, "local role to assign; repeat as needed")
	cmd.Flags().StringSliceVar(&localGroups, "local-group", nil, "local group to assign; repeat as needed")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("issuer")
	_ = cmd.MarkFlagRequired("subject")
	rootCmd.AddCommand(cmd)
}
