package cmd

import (
	"fmt"

	"uvoo-certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var shareID string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "revoke-share",
		Short: "Revoke a certificate share",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if err := store.RevokeShare(shareID); err != nil {
				return err
			}
			logAuditEvent(store, "revoke_share", "share", shareID, "")
			if jsonOut {
				return printJSON(map[string]any{
					"share_id": shareID,
					"status":   "revoked",
				})
			}
			fmt.Printf("Revoked share %s\n", shareID)
			return nil
		},
	}

	cmd.Flags().StringVar(&shareID, "share-id", "", "share ID to revoke")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("share-id")

	rootCmd.AddCommand(cmd)
}
