package cmd

import (
	"fmt"
	"time"

	"certctl/internal/acme"
	"certctl/internal/cli"
	"certctl/internal/dns"
	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var flags providerFlags
	var domain, email, password string
	var timeout, propagation time.Duration
	var skipChecks, staging bool

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
			if !skipChecks {
				fmt.Println("Running precursor checks before issuance...")
				if err := dns.CheckPrecursors(ctx, p, domain, flags.DNSResolver, false); err != nil {
					return err
				}
			}
			certs, err := acme.Issue(ctx, acme.IssueOptions{
				Email:       email,
				Domain:      domain,
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
			if err := store.Upsert(storage.Record{
				Domain:    domain,
				CertPEM:   encCert,
				KeyPEM:    encKey,
				Provider:  flags.Provider,
				Email:     email,
				Issuer:    issuer,
				NotBefore: notBefore,
				NotAfter:  notAfter,
			}); err != nil {
				return err
			}
			fmt.Printf("Successfully obtained and stored certificate for %s\n", domain)
			printKV("issuer", issuer)
			printKV("not before", notBefore.Format(time.RFC3339))
			printKV("not after", notAfter.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "target domain or wildcard domain")
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
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("email")
	_ = cmd.MarkFlagRequired("password")
	_ = cmd.MarkFlagRequired("provider")
	rootCmd.AddCommand(cmd)
}
