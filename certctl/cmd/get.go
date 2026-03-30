package cmd

import (
	"fmt"
	"strings"
	"time"

	"certctl/internal/acme"
	"certctl/internal/cli"
	"certctl/internal/dns"
	"certctl/internal/storage"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func buildSANSet(commonName string, sans []string, includeRoot bool) []string {
	seen := map[string]bool{}
	var out []string

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	add(commonName)

	for _, s := range sans {
		for part := range strings.SplitSeq(s, ",") {
			add(part)
		}
	}

	if includeRoot {
		var extra []string
		for _, d := range out {
			if after, ok := strings.CutPrefix(d, "*."); ok {
				extra = append(extra, after)
			}
		}
		for _, e := range extra {
			add(e)
		}
	}

	return out
}

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

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Obtain a Let's Encrypt certificate and store it encrypted in SQLite",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := withTimeout(timeout)
			defer cancel()

			p, err := providerFromFlags(ctx, flags)
			if err != nil {
				return err
			}

			if keyPassword != "" {
				if err := util.IsPasswordComplex(keyPassword); err != nil {
					return fmt.Errorf("invalid key-password: %w", err)
				}
			}
			if storagePassword != "" {
				if err := util.IsPasswordComplex(storagePassword); err != nil {
					return fmt.Errorf("invalid storage-password: %w", err)
				}
			}

			commonName = strings.TrimSpace(commonName)
			if commonName == "" {
				return fmt.Errorf("--common-name is required")
			}

			allSANs := buildSANSet(commonName, sans, includeRoot)
			_, sansCSV, sansHash := storage.NormalizeSANs(allSANs)

			skipIfExpiresWithin, err := util.ParseFlexibleDuration(skipIfExpiresWithinRaw)
			if err != nil {
				return fmt.Errorf("invalid --skip-if-expires-within: %w", err)
			}

			if !skipChecks {
				fmt.Println("Running precursor checks before issuance...")
				if err := dns.CheckPrecursors(ctx, p, commonName, flags.DNSResolver, false); err != nil {
					return err
				}
			}

			certs, err := acme.Issue(ctx, acme.IssueOptions{
				Email:       email,
				Domains:     allSANs,
				Provider:    flags.Provider,
				APIUser:     flags.APIUser,
				APIKey:      flags.APIKey,
				ClientIP:    flags.ClientIP,
				Timeout:     timeout,
				UseStaging:  staging,
				Propagation: propagation,
				KeyType:     keyType,
			})
			if err != nil {
				return err
			}

			cryptoPassword, err := util.ResolveCryptoPassword(keyPassword, storagePassword)
			if err != nil {
				return err
			}

			plainCert := certs.Certificate
			encKey, err := cli.Encrypt(certs.PrivateKey, cryptoPassword)
			if err != nil {
				return err
			}

			issuer, notBefore, notAfter, err := storage.ParseCertMetadata(certs.Certificate)
			if err != nil {
				return err
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if !force {
				if existing, err := store.FindByHash(commonName, sansHash); err == nil {
					remaining := time.Until(existing.NotAfter)
					if remaining > skipIfExpiresWithin {
						fmt.Printf("[info] identical cert already exists for %s\n", commonName)
						fmt.Printf("[info] SANs: %s\n", existing.SANsCSV)
						fmt.Printf("[info] expires: %s\n", existing.NotAfter.Format(time.RFC3339))
						fmt.Printf("[info] remaining: %s\n", remaining.Round(time.Second))
						fmt.Printf("[info] skipping issuance because remaining lifetime exceeds %s\n", skipIfExpiresWithin)
						return nil
					}

					fmt.Printf("[info] identical cert exists but expires within %s; continuing issuance\n", skipIfExpiresWithin)
				}
			}

			if _, err := store.FindByHash(commonName, sansHash); err == nil {
				fmt.Println("[info] identical cert already exists, skipping issuance")
				return nil
			}

			if err := store.Upsert(storage.PublicCert{
				ID:         util.NewID(),
				CommonName: commonName,
				SANsCSV:    sansCSV,
				SANsHash:   sansHash,
				CertPEM:    plainCert,
				KeyPEM:     encKey,
				Provider:   flags.Provider,
				Email:      email,
				Issuer:     issuer,
				NotBefore:  notBefore,
				NotAfter:   notAfter,
			}); err != nil {
				return err
			}

			fmt.Printf("Successfully obtained and stored certificate for %s\n", commonName)
			fmt.Printf("names: %s\n", strings.Join(allSANs, ", "))
			fmt.Printf("[info] SAN set: %s\n", sansCSV)
			printKV("issuer", issuer)
			printKV("not before", notBefore.Format(time.RFC3339))
			printKV("not after", notAfter.Format(time.RFC3339))
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

	_ = cmd.MarkFlagRequired("common-name")
	_ = cmd.MarkFlagRequired("email")
	_ = cmd.MarkFlagRequired("provider")
	rootCmd.AddCommand(cmd)
}
