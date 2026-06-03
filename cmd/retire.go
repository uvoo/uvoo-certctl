package cmd

import (
	"fmt"

	"uvoo-certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var kind string
	var id string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "retire",
		Short: "Retire a private CA from issuance",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			switch kind {
			case "root":
				err = store.RetirePrivateRootCA(id)
			case "intermediate":
				err = store.RetirePrivateIntermediateCA(id)
			default:
				return fmt.Errorf("--kind must be root or intermediate")
			}
			if err != nil {
				return err
			}
			logAuditEvent(store, "retire", "private_"+kind+"_ca", id, "")
			if jsonOut {
				return printJSON(map[string]any{
					"kind":   kind,
					"id":     id,
					"status": "retired",
				})
			}

			fmt.Printf("Retired %s CA %s\n", kind, id)
			return nil
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "CA kind: root or intermediate")
	cmd.Flags().StringVar(&id, "id", "", "CA ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("id")
	rootCmd.AddCommand(cmd)
}
