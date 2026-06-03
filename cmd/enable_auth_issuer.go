package cmd

import (
	"fmt"

	"uvoo-certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var issuer string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:     "enable-auth-issuer",
		Short:   "Enable a trusted JWT/OIDC issuer",
		Example: `  uvoo-certctl enable-auth-issuer --issuer https://sso.example.com/realms/uvoo-certctl`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if err := store.SetAuthIssuerEnabled(issuer, true); err != nil {
				return err
			}
			rec, err := store.GetAuthIssuerByIssuer(issuer)
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(authIssuerPayload(rec))
			}
			fmt.Printf("Enabled auth issuer %s\n", rec.Name)
			printKV("issuer", rec.Issuer)
			return nil
		},
	}

	cmd.Flags().StringVar(&issuer, "issuer", "", "issuer URL to enable")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("issuer")
	rootCmd.AddCommand(cmd)
}
