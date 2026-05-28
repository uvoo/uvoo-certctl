package cmd

import (
	"fmt"

	"uvoocertctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var name string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "delete-subject-auto-approval",
		Short: "Delete a subject auto-approval rule",
		Example: `  uvoocertctl delete-subject-auto-approval --name google-employees
  uvoocertctl delete-subject-auto-approval --name google-employees --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := store.GetSubjectAutoApprovalRuleByName(name)
			if err != nil {
				return err
			}
			if err := store.DeleteSubjectAutoApprovalRule(name); err != nil {
				return err
			}
			logAuditEvent(store, "delete_subject_auto_approval", "subject_auto_approval_rule", rec.Name, rec.Issuer)

			if jsonOut {
				return printJSON(map[string]any{
					"name":    rec.Name,
					"issuer":  rec.Issuer,
					"deleted": true,
				})
			}
			fmt.Printf("Deleted subject auto approval %s\n", rec.Name)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "rule name to delete")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("name")
	rootCmd.AddCommand(cmd)
}
