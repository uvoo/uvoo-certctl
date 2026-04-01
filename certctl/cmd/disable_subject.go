package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var issuer string
	var subject string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "disable-subject",
		Short: "Disable a locally tracked JWT subject",
		Example: `  certctl disable-subject --issuer https://sso.example.com/realms/certctl --subject user-123
  certctl disable-subject --issuer https://sso.example.com/realms/certctl --subject user-123 --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if err := store.SetSubjectStatus(issuer, subject, storage.SubjectStatusDisabled); err != nil {
				return err
			}
			rec, err := store.GetSubject(issuer, subject)
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(subjectPayload(rec))
			}
			fmt.Printf("Disabled subject %s\n", rec.Subject)
			printKV("issuer", rec.Issuer)
			return nil
		},
	}

	cmd.Flags().StringVar(&issuer, "issuer", "", "issuer URL for the subject")
	cmd.Flags().StringVar(&subject, "subject", "", "subject value to disable")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("issuer")
	_ = cmd.MarkFlagRequired("subject")
	rootCmd.AddCommand(cmd)
}
