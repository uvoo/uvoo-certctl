package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var limit int
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-audit",
		Short: "List recent audit events",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.ListAuditEvents(limit)
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(rows)
			}
			for _, row := range rows {
				fmt.Printf("%s  %s  %s  %s  %s\n", formatTimeValue(row.CreatedAt), row.Action, row.TargetKind, row.TargetID, row.Summary)
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 100, "maximum number of events to show")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
