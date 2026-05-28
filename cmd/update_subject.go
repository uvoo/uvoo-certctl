package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var issuer string
	var subject string
	var status string
	var localRoles []string
	var localGroups []string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "update-subject",
		Short: "Update a locally tracked JWT subject",
		Example: `  certctl update-subject --issuer https://accounts.google.com --subject user-123 --status active
  certctl update-subject --issuer https://accounts.google.com --subject user-123 --local-group viewers
  certctl update-subject --issuer https://accounts.google.com --subject user-123 --local-role admin --local-group ops --json`,
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

			nextStatus := rec.Status
			if cmd.Flags().Changed("status") {
				nextStatus = status
			}
			nextRoles := rec.LocalRoles
			if cmd.Flags().Changed("local-role") {
				nextRoles = compactStrings(localRoles)
			}
			nextGroups := rec.LocalGroups
			if cmd.Flags().Changed("local-group") {
				nextGroups = compactStrings(localGroups)
			}
			if !cmd.Flags().Changed("status") && !cmd.Flags().Changed("local-role") && !cmd.Flags().Changed("local-group") {
				return fmt.Errorf("at least one of --status, --local-role, or --local-group is required")
			}

			if err := store.UpdateSubjectApproval(issuer, subject, nextStatus, nextRoles, nextGroups); err != nil {
				return err
			}
			rec, err = store.GetSubject(issuer, subject)
			if err != nil {
				return err
			}
			logAuditEvent(store, "update_subject", "subject", rec.ID, rec.Issuer+" "+rec.Subject)

			if jsonOut {
				return printJSON(subjectPayload(rec))
			}
			fmt.Printf("Updated subject %s\n", rec.Subject)
			printKV("issuer", rec.Issuer)
			printKV("status", rec.Status)
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
	cmd.Flags().StringVar(&subject, "subject", "", "subject value to update")
	cmd.Flags().StringVar(&status, "status", "", "subject status: pending, active, disabled")
	cmd.Flags().StringSliceVar(&localRoles, "local-role", nil, "replace local roles with the provided values; repeat as needed")
	cmd.Flags().StringSliceVar(&localGroups, "local-group", nil, "replace local groups with the provided values; repeat as needed")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("issuer")
	_ = cmd.MarkFlagRequired("subject")
	rootCmd.AddCommand(cmd)
}
