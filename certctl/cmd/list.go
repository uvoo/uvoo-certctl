package cmd

import (
	"fmt"
	"time"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var domain string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.List(domain)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				if domain != "" {
					fmt.Printf("No certificates found for domain: %s\n", domain)
				} else {
					fmt.Println("No certificates found")
				}
				return nil
			}

			for _, r := range rows {
				fmt.Printf("domain: %s\n", r.Domain)
				fmt.Printf("  sans:       %s\n", r.DomainsCSV)
				fmt.Printf("  provider:   %s\n", r.Provider)
				fmt.Printf("  email:      %s\n", r.Email)
				fmt.Printf("  issuer:     %s\n", r.Issuer)
				fmt.Printf("  not before: %s\n", r.NotBefore.Format(time.RFC3339))
				fmt.Printf("  not after:  %s\n", r.NotAfter.Format(time.RFC3339))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "filter by domain")
	rootCmd.AddCommand(cmd)
}
