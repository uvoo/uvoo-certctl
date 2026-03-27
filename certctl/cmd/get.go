package cmd

import (
	"fmt"
	"time"

	"certctl/internal/acme"
	"certctl/internal/cli"
	"certctl/internal/dns"
	"certctl/internal/storage"
	"certctl/internal/util"
	// "github.com/google/uuid"
	"github.com/spf13/cobra"
	"strings"
)

/*
func newID() string {
	return uuid.NewString()
}
*/

func buildDomainSet(domains, sans []string, includeRoot bool) []string {
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

	for _, d := range domains {
		for _, part := range strings.Split(d, ",") {
			add(part)
		}
	}
	for _, s := range sans {
		for _, part := range strings.Split(s, ",") {
			add(part)
		}
	}

	if includeRoot {
		var extra []string
		for _, d := range out {
			if strings.HasPrefix(d, "*.") {
				extra = append(extra, strings.TrimPrefix(d, "*."))
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
	var domains, sans []string
	var email, password string
	var includeRoot bool
	var timeout, propagation time.Duration
	var skipChecks, staging bool
	// var skipIfExpiresWithin time.Duration
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
			allDomains := buildDomainSet(domains, sans, includeRoot)
			if len(allDomains) == 0 {
				return fmt.Errorf("at least one domain is required")
			}
			// primaryDomain := allDomains[0]
			normalized, csv, hash := storage.NormalizeDomains(allDomains)
			primaryDomain := storage.PickPrimary(normalized)

			skipIfExpiresWithin, err := util.ParseFlexibleDuration(skipIfExpiresWithinRaw)
			if err != nil {
				return fmt.Errorf("invalid --skip-if-expires-within: %w", err)
			}

			if !skipChecks {
				fmt.Println("Running precursor checks before issuance...")
				if err := dns.CheckPrecursors(ctx, p, primaryDomain, flags.DNSResolver, false); err != nil {
					return err
				}
			}
			certs, err := acme.Issue(ctx, acme.IssueOptions{
				Email:       email,
				Domains:     allDomains,
				Provider:    flags.Provider,
				APIUser:     flags.APIUser,
				APIKey:      flags.APIKey,
				ClientIP:    flags.ClientIP,
				Timeout:     timeout,
				UseStaging:  staging,
				Propagation: propagation,
			})
			if err != nil {
				return err
			}
			encCert, err := cli.Encrypt(certs.Certificate, password)
			if err != nil {
				return err
			}
			encKey, err := cli.Encrypt(certs.PrivateKey, password)
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
				if existing, err := store.FindByHash(primaryDomain, hash); err == nil {
					remaining := time.Until(existing.NotAfter)
					if remaining > skipIfExpiresWithin {
						fmt.Printf("[info] identical cert already exists for %s\n", primaryDomain)
						fmt.Printf("[info] SANs: %s\n", existing.DomainsCSV)
						fmt.Printf("[info] expires: %s\n", existing.NotAfter.Format(time.RFC3339))
						fmt.Printf("[info] remaining: %s\n", remaining.Round(time.Second))
						fmt.Printf("[info] skipping issuance because remaining lifetime exceeds %s\n", skipIfExpiresWithin)
						return nil
					}

					fmt.Printf("[info] identical cert exists but expires within %s; continuing issuance\n", skipIfExpiresWithin)
				}
			}

			if _, err := store.FindByHash(primaryDomain, hash); err == nil {
				fmt.Println("[info] identical cert already exists, skipping issuance")
				return nil
			}
			/*
			 */
			// primaryDomain := allDomains[0]
			if err := store.Upsert(storage.Record{
				ID:          util.NewID(),
				Domain:      primaryDomain,
				DomainsCSV:  csv,
				DomainsHash: hash,
				CertPEM:     encCert,
				KeyPEM:      encKey,
				Provider:    flags.Provider,
				Email:       email,
				Issuer:      issuer,
				NotBefore:   notBefore,
				NotAfter:    notAfter,
			}); err != nil {
				return err
			}
			fmt.Printf("Successfully obtained and stored certificate for %s\n", primaryDomain)
			fmt.Printf("domains: %s\n", strings.Join(allDomains, ", "))
			fmt.Printf("[info] SAN set: %s\n", csv)
			printKV("issuer", issuer)
			printKV("not before", notBefore.Format(time.RFC3339))
			printKV("not after", notAfter.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&domains, "domain", nil, "target domain(s); can be specified multiple times or comma-separated")
	cmd.Flags().StringSliceVar(&sans, "san", nil, "additional SANs; can be specified multiple times or comma-separated")
	cmd.Flags().BoolVar(&includeRoot, "include-root", false, "if a wildcard is present, also include the apex/root domain")
	_ = cmd.MarkFlagRequired("domain")

	cmd.Flags().StringVar(&email, "email", "", "ACME account email")
	cmd.Flags().StringVar(&password, "password", "", "encryption password for stored cert material")
	cmd.Flags().StringVar(&flags.Provider, "provider", "", "dns provider: godaddy or namecheap")
	cmd.Flags().StringVar(&flags.APIUser, "api-user", "", "provider API user/key id")
	cmd.Flags().StringVar(&flags.APIKey, "api-key", "", "provider API secret/key")
	cmd.Flags().StringVar(&flags.ClientIP, "client-ip", "", "namecheap whitelisted client IP")
	cmd.Flags().StringVar(&flags.DNSResolver, "dns-resolver", "8.8.8.8", "resolver used for prerequisite DNS lookup")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "overall ACME timeout")
	cmd.Flags().DurationVar(&propagation, "propagation-timeout", 30*time.Minute, "DNS propagation timeout for provider checks")
	cmd.Flags().BoolVar(&skipChecks, "skip-checks", false, "skip precursor checks")
	cmd.Flags().BoolVar(&staging, "staging", false, "use Let's Encrypt staging")
/*
	cmd.Flags().DurationVar(
		&skipIfExpiresWithin,
		"skip-if-expires-within",
		14*24*time.Hour,
		"skip issuance if an identical cert already exists and expires later than this duration (e.g. 240h, 14d if your parser supports it)",
	)
*/
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
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("email")
	_ = cmd.MarkFlagRequired("password")
	_ = cmd.MarkFlagRequired("provider")
	rootCmd.AddCommand(cmd)
}
