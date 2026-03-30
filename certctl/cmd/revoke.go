package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var kind string
	var id string

	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a stored certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			switch kind {
			case "public":
				err = store.RevokePublicCert(id)
			case "private":
				err = store.RevokePrivateCert(id)
			default:
				return fmt.Errorf("--kind must be public or private")
			}
			if err != nil {
				return err
			}

			fmt.Printf("Revoked %s certificate %s\n", kind, id)
			return nil
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "certificate kind: public or private")
	cmd.Flags().StringVar(&id, "id", "", "certificate ID")
	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("id")
	rootCmd.AddCommand(cmd)
}
