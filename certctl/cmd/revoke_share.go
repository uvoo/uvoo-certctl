package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var shareID string

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
			fmt.Printf("Revoked share %s\n", shareID)
			return nil
		},
	}

	cmd.Flags().StringVar(&shareID, "share-id", "", "share ID to revoke")
	_ = cmd.MarkFlagRequired("share-id")

	rootCmd.AddCommand(cmd)
}
