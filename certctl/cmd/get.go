package cmd

import (
	"fmt"
	"strings"
	"time"

	"certctl/internal/ops"
	"certctl/internal/storage"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var flags providerFlags
	var commonName string
	var sans []string
	var email, keyPassword, storagePassword, keyType string
	var includeRoot bool
	var timeout, propagation time.Duration
	var skipChecks, staging bool
	var force bool
	var skipIfExpiresWithinRaw string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Obtain a Let's Encrypt certificate and store it encrypted in SQLite",
		Example: `  certctl get \
    --common-name '*.example.com' \
    --sans '*.example.com,example.com' \
    --provider godaddy \
    --email admin@example.com \
    --storage-password env:CERTCTL_STORAGE_PASSWORD \
    --api-user "$GODADDY_API_KEY" \
    --api-key "$GODADDY_API_SECRET"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			keyPassword, err := util.ResolveSecretValue(keyPassword, "CERTCTL_KEY_PASSWORD")
			if err != nil {
				return err
			}
			storagePassword, err = util.ResolveSecretValue(storagePassword, "CERTCTL_STORAGE_PASSWORD")
			if err != nil {
				return err
			}

			if err := ops.ValidatePublicIssuePasswords(keyPassword, storagePassword); err != nil {
				return err
			}

			commonName = strings.TrimSpace(commonName)
			if commonName == "" {
				return fmt.Errorf("--common-name is required")
			}

			allSANs := ops.BuildPublicSANSet(commonName, sans, includeRoot)

			skipIfExpiresWithin, err := util.ParseFlexibleDuration(skipIfExpiresWithinRaw)
			if err != nil {
				return fmt.Errorf("invalid --skip-if-expires-within: %w", err)
			}
			if !skipChecks {
				fmt.Println("Running precursor checks before issuance...")
			}

			cryptoPassword, err := util.ResolveCryptoPassword(keyPassword, storagePassword)
			if err != nil {
				return err
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			result, err := ops.IssuePublicCert(store, ops.IssuePublicCertParams{
				Provider: ops.ProviderConfig{
					Provider:    flags.Provider,
					APIUser:     flags.APIUser,
					APIKey:      flags.APIKey,
					ClientIP:    flags.ClientIP,
					DNSResolver: flags.DNSResolver,
					HTTPTimeout: rootCfg.HTTPTimeout,
				},
				CommonName:          commonName,
				SANs:                allSANs,
				Email:               email,
				KeyType:             keyType,
				Timeout:             timeout,
				Propagation:         propagation,
				SkipChecks:          skipChecks,
				Staging:             staging,
				Force:               force,
				SkipIfExpiresWithin: skipIfExpiresWithin,
				CryptoPassword:      cryptoPassword,
			})
			if err != nil {
				return err
			}
			printSANConflicts(result.Warnings)
			if result.Skipped {
				if !result.Record.NotAfter.IsZero() {
					remaining := time.Until(result.Record.NotAfter)
					fmt.Printf("[info] identical cert already exists for %s\n", commonName)
					fmt.Printf("[info] SANs: %s\n", result.Record.SANsCSV)
					fmt.Printf("[info] expires: %s\n", result.Record.NotAfter.Format(time.RFC3339))
					fmt.Printf("[info] remaining: %s\n", remaining.Round(time.Second))
					if !force {
						fmt.Printf("[info] skipping issuance because remaining lifetime exceeds %s\n", skipIfExpiresWithin)
					}
				} else {
					fmt.Println("[info] identical cert already exists, skipping issuance")
				}
				return nil
			}
			rec := result.Record
			if jsonOut {
				return printJSON(map[string]any{
					"id":          rec.ID,
					"common_name": rec.CommonName,
					"sans_csv":    rec.SANsCSV,
					"provider":    rec.Provider,
					"email":       rec.Email,
					"issuer":      rec.Issuer,
					"status":      rec.Status,
					"not_before":  formatTimeValue(rec.NotBefore),
					"not_after":   formatTimeValue(rec.NotAfter),
				})
			}

			fmt.Printf("Successfully obtained and stored certificate for %s\n", commonName)
			fmt.Printf("names: %s\n", strings.Join(allSANs, ", "))
			fmt.Printf("[info] SAN set: %s\n", rec.SANsCSV)
			printKV("issuer", rec.Issuer)
			printKV("not before", rec.NotBefore.Format(time.RFC3339))
			printKV("not after", rec.NotAfter.Format(time.RFC3339))
			return nil
		},
	}

	cmd.Flags().StringVar(&commonName, "common-name", "", "certificate common name (CN)")
	cmd.Flags().StringSliceVar(&sans, "sans", nil, "subject alternative names (SANs); can be specified multiple times or comma-separated")
	cmd.Flags().BoolVar(&includeRoot, "include-root", false, "if a wildcard is present, also include the apex/root domain")

	cmd.Flags().StringVar(&email, "email", "", "ACME account email")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "per-certificate encryption password for stored cert material")
	cmd.Flags().StringVar(&storagePassword, "storage-password", "", "fallback encryption password used when --key-password is not provided")
	cmd.Flags().StringVar(&keyType, "key-type", "ec256", "certificate key type: ec256, ec384, rsa2048, rsa4096")
	cmd.Flags().StringVar(&flags.Provider, "provider", "", "dns provider: godaddy or namecheap")
	cmd.Flags().StringVar(&flags.APIUser, "api-user", "", "provider API user/key id")
	cmd.Flags().StringVar(&flags.APIKey, "api-key", "", "provider API secret/key")
	cmd.Flags().StringVar(&flags.ClientIP, "client-ip", "", "namecheap whitelisted client IP")
	cmd.Flags().StringVar(&flags.DNSResolver, "dns-resolver", "8.8.8.8", "resolver used for prerequisite DNS lookup")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "overall ACME timeout")
	cmd.Flags().DurationVar(&propagation, "propagation-timeout", 30*time.Minute, "DNS propagation timeout for provider checks")
	cmd.Flags().BoolVar(&skipChecks, "skip-checks", false, "skip precursor checks")
	cmd.Flags().BoolVar(&staging, "staging", false, "use Let's Encrypt staging")
	cmd.Flags().StringVar(
		&skipIfExpiresWithinRaw,
		"skip-if-expires-within",
		"14d",
		"skip issuance if an identical cert already exists and expires later than this duration",
	)
	cmd.Flags().BoolVar(
		&force,
		"force",
		false,
		"force issuance even if an identical cert already exists",
	)
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")

	_ = cmd.MarkFlagRequired("common-name")
	_ = cmd.MarkFlagRequired("email")
	_ = cmd.MarkFlagRequired("provider")
	rootCmd.AddCommand(cmd)
}
