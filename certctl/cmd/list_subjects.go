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
	var subject string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-subjects",
		Short: "List observed JWT subjects",
		Example: `  certctl list-subjects
  certctl list-subjects --all --json
  certctl list-subjects --issuer https://sso.example.com/realms/certctl`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.ListSubjects(!all)
			if err != nil {
				return err
			}

			filtered := make([]storage.Subject, 0, len(rows))
			for _, row := range rows {
				if issuer != "" && row.Issuer != strings.TrimSpace(issuer) {
					continue
				}
				if subject != "" && row.Subject != strings.TrimSpace(subject) {
					continue
				}
				filtered = append(filtered, row)
			}

			if jsonOut {
				payload := make([]map[string]any, 0, len(filtered))
				for _, row := range filtered {
					payload = append(payload, subjectPayload(row))
				}
				return printJSON(payload)
			}
			if len(filtered) == 0 {
				fmt.Println("No subjects found")
				return nil
			}
			for _, row := range filtered {
				printKV("issuer", row.Issuer)
				printKV("subject", row.Subject)
				printKV("status", row.Status)
				if row.Username != "" {
					printKV("username", row.Username)
				}
				if row.Email != "" {
					printKV("email", row.Email)
				}
				printKV("auth_count", fmt.Sprintf("%d", row.AuthCount))
				if !row.LastSeenAt.IsZero() {
					printKV("last_seen_at", row.LastSeenAt.Format("2006-01-02T15:04:05Z07:00"))
				}
				fmt.Println()
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "include disabled subjects")
	cmd.Flags().StringVar(&issuer, "issuer", "", "filter by issuer URL")
	cmd.Flags().StringVar(&subject, "subject", "", "filter by subject value")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
