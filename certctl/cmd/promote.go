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
		Use:   "promote",
		Short: "Promote a private CA generation back to active issuing status",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			switch kind {
			case "root":
				err = store.PromotePrivateRootCA(id)
			case "intermediate":
				err = store.PromotePrivateIntermediateCA(id)
			default:
				return fmt.Errorf("--kind must be root or intermediate")
			}
			if err != nil {
				return err
			}

			fmt.Printf("Promoted %s CA %s\n", kind, id)
			return nil
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "CA kind: root or intermediate")
	cmd.Flags().StringVar(&id, "id", "", "CA ID")
	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("id")
	rootCmd.AddCommand(cmd)
}
