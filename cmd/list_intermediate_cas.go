package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var name string
	var all bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-intermediate-cas",
		Short: "List stored private intermediate CAs",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.ListPrivateIntermediateCAs(name, all)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Println("No private intermediate CAs found")
				return nil
			}

			if jsonOut {
				var payload []map[string]any
				for _, row := range rows {
					payload = append(payload, map[string]any{
						"id":               row.ID,
						"root_ca_id":       row.RootCAID,
						"name":             row.Name,
						"common_name":      row.CommonName,
						"generation":       row.Generation,
						"status":           row.Status,
						"is_trusted":       row.IsTrusted,
						"is_issuing":       row.IsIssuing,
						"supersedes_ca_id": row.SupersedesCAID,
						"key_type":         row.KeyType,
						"issuer":           row.Issuer,
						"not_before":       formatTimeValue(row.NotBefore),
						"not_after":        formatTimeValue(row.NotAfter),
						"created_at":       formatTimeValue(row.CreatedAt),
						"updated_at":       formatTimeValue(row.UpdatedAt),
					})
				}
				return printJSON(payload)
			}

			for _, row := range rows {
				fmt.Printf("id:           %s\n", row.ID)
				fmt.Printf("rootId:       %s\n", row.RootCAID)
				fmt.Printf("name:         %s\n", row.Name)
				fmt.Printf("generation:   %d\n", row.Generation)
				fmt.Printf("status:       %s\n", row.Status)
				fmt.Printf("isTrusted:    %t\n", row.IsTrusted)
				fmt.Printf("isIssuing:    %t\n", row.IsIssuing)
				fmt.Printf("commonName:   %s\n", row.CommonName)
				fmt.Printf("keyType:      %s\n", row.KeyType)
				fmt.Printf("issuer:       %s\n", row.Issuer)
				fmt.Printf("notBefore:    %s\n", formatTimeValue(row.NotBefore))
				fmt.Printf("notAfter:     %s\n", formatTimeValue(row.NotAfter))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "filter by logical name")
	cmd.Flags().BoolVar(&all, "all", false, "include inactive and historical CAs")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
