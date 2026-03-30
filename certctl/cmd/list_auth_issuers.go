package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var all bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-auth-issuers",
		Short: "List trusted JWT/OIDC issuers",
		Example: `  certctl list-auth-issuers
  certctl list-auth-issuers --all --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.ListAuthIssuers(!all)
			if err != nil {
				return err
			}
			if jsonOut {
				payload := make([]map[string]any, 0, len(rows))
				for _, row := range rows {
					payload = append(payload, authIssuerPayload(row))
				}
				return printJSON(payload)
			}
			if len(rows) == 0 {
				fmt.Println("No auth issuers found")
				return nil
			}
			for _, row := range rows {
				printKV("id", row.ID)
				printKV("name", row.Name)
				printKV("issuer", row.Issuer)
				printKV("enabled", fmt.Sprintf("%t", row.Enabled))
				printKV("audiences", fmt.Sprintf("%v", row.Audiences))
				fmt.Println()
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "include disabled issuers")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
