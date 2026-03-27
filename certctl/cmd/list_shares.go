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
		Use:   "list-shares",
		Short: "List certificate shares",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			var certID string
			if domain != "" {
				rec, err := store.GetByDomain(domain)
				if err != nil {
					return err
				}
				certID = rec.ID
			}

			shares, err := store.ListShares(certID)
			if err != nil {
				return err
			}
			if len(shares) == 0 {
				fmt.Println("No shares found")
				return nil
			}

			for _, sh := range shares {
				fmt.Printf("share id:   %s\n", sh.ID)
				fmt.Printf("  cert id:  %s\n", sh.CertID)
				fmt.Printf("  mode:     %s\n", sh.Mode)
				fmt.Printf("  token:    %s\n", sh.ShareToken)
				if !sh.ExpiresAt.IsZero() {
					fmt.Printf("  expires:  %s\n", sh.ExpiresAt.Format(time.RFC3339))
				}
				if sh.MaxViews.Valid {
					fmt.Printf("  maxViews: %d\n", sh.MaxViews.Int64)
				}
				fmt.Printf("  views:    %d\n", sh.ViewCount)
				if !sh.RevokedAt.IsZero() {
					fmt.Printf("  revoked:  %s\n", sh.RevokedAt.Format(time.RFC3339))
				}
				if sh.Note != "" {
					fmt.Printf("  note:     %s\n", sh.Note)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "filter shares by certificate domain")
	rootCmd.AddCommand(cmd)
}
