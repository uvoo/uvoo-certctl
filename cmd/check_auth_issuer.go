package cmd

import (
	"context"
	"fmt"
	"time"

	"uvoo-certctl/internal/auth"
	"uvoo-certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var issuer string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "check-auth-issuer",
		Short: "Check live discovery and JWKS connectivity for a trusted JWT/OIDC issuer",
		Example: `  uvoo-certctl check-auth-issuer --issuer https://sso.example.com/realms/uvoo-certctl
  uvoo-certctl check-auth-issuer --issuer https://sso.example.com/realms/uvoo-certctl --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := store.GetAuthIssuerByIssuer(issuer)
			if err != nil {
				return err
			}

			timeout := rootCfg.HTTPTimeout
			if timeout <= 0 {
				timeout = defaultCheckAuthIssuerTimeout
			}
			verifier := auth.NewVerifier(timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			result, err := verifier.CheckIssuer(ctx, rec)

			payload := map[string]any{
				"ok":                 err == nil,
				"issuer":             rec.Issuer,
				"name":               rec.Name,
				"enabled":            rec.Enabled,
				"expected_audiences": rec.Audiences,
				"required_claims":    rec.RequiredClaims,
				"discovery_url":      result.DiscoveryURL,
				"jwks_url":           result.JWKSURL,
				"jwks_key_count":     result.KeyCount,
			}
			if err != nil {
				payload["error"] = err.Error()
			}

			if jsonOut {
				return printJSON(payload)
			}

			if err != nil {
				fmt.Printf("Auth issuer check failed for %s\n", rec.Name)
				printKV("issuer", rec.Issuer)
				printKV("error", err.Error())
				return nil
			}

			fmt.Printf("Auth issuer check ok for %s\n", rec.Name)
			printKV("issuer", rec.Issuer)
			printKV("jwks_url", result.JWKSURL)
			printKV("jwks_keys", fmt.Sprintf("%d", result.KeyCount))
			return nil
		},
	}

	cmd.Flags().StringVar(&issuer, "issuer", "", "issuer URL to check")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("issuer")
	rootCmd.AddCommand(cmd)
}

const defaultCheckAuthIssuerTimeout = 10 * time.Second
