package cmd

import (
	"fmt"
	"time"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var san string
	var jsonOut bool

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
			if san != "" {
				rec, err := store.GetBySAN(san)
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
			if jsonOut {
				var payload []map[string]any
				for _, sh := range shares {
					payload = append(payload, map[string]any{
						"id":             sh.ID,
						"cert_kind":      sh.CertKind,
						"cert_id":        sh.CertID,
						"share_token":    sh.ShareToken,
						"mode":           sh.Mode,
						"expires_at":     formatTimeValue(sh.ExpiresAt),
						"max_views":      nullableInt64Value(sh.MaxViews),
						"view_count":     sh.ViewCount,
						"created_at":     formatTimeValue(sh.CreatedAt),
						"last_viewed_at": formatTimeValue(sh.LastViewedAt),
						"revoked_at":     formatTimeValue(sh.RevokedAt),
						"note":           sh.Note,
					})
				}
				return printJSON(payload)
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

	cmd.Flags().StringVar(&san, "san", "", "filter shares by certificate san")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
