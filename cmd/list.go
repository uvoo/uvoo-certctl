package cmd

import (
	"fmt"
	"time"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var san string
	var all bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.List(san, all)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				if san != "" {
					fmt.Printf("No certificates found for common_name or san: %s\n", san)
				} else {
					fmt.Println("No certificates found")
				}
				return nil
			}
			if jsonOut {
				var payload []map[string]any
				for _, r := range rows {
					payload = append(payload, map[string]any{
						"id":                 r.ID,
						"common_name":        r.CommonName,
						"sans_csv":           r.SANsCSV,
						"provider":           r.Provider,
						"email":              r.Email,
						"issuer":             r.Issuer,
						"status":             r.Status,
						"supersedes_cert_id": r.SupersedesCertID,
						"revoked_at":         formatTimeValue(r.RevokedAt),
						"not_before":         formatTimeValue(r.NotBefore),
						"not_after":          formatTimeValue(r.NotAfter),
						"created_at":         formatTimeValue(r.CreatedAt),
						"updated_at":         formatTimeValue(r.UpdatedAt),
						"private_key_stored": privateKeyStored(r.KeyPEM),
					})
				}
				return printJSON(payload)
			}

			for _, r := range rows {
				fmt.Printf("id:          %s\n", r.ID)
				fmt.Printf("common_name: %s\n", r.CommonName)
				fmt.Printf("  status:     %s\n", r.Status)
				fmt.Printf("  sans:       %s\n", r.SANsCSV)
				fmt.Printf("  provider:   %s\n", r.Provider)
				fmt.Printf("  email:      %s\n", r.Email)
				fmt.Printf("  issuer:     %s\n", r.Issuer)
				fmt.Printf("  key stored: %t\n", privateKeyStored(r.KeyPEM))
				fmt.Printf("  not before: %s\n", r.NotBefore.Format(time.RFC3339))
				fmt.Printf("  not after:  %s\n", r.NotAfter.Format(time.RFC3339))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&san, "san", "", "filter by san")
	cmd.Flags().BoolVar(&all, "all", false, "include inactive and historical certificates")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
