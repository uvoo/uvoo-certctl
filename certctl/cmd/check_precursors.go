package cmd

import (
	"fmt"
	"time"

	"certctl/internal/dns"
	"github.com/spf13/cobra"
)

func init() {
	var flags providerFlags
	var domain string
	var timeout time.Duration
	var writeTest bool

	cmd := &cobra.Command{
		Use:   "check-precursors",
		Short: "Validate provider auth, zone access, and basic DNS prerequisites",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := withTimeout(timeout)
			defer cancel()
			p, err := providerFromFlags(ctx, flags)
			if err != nil {
				return err
			}
			fmt.Println("[1/4] Checking provider credentials...")
			if err := p.CheckCredentials(ctx); err != nil {
				return err
			}
			fmt.Println("[ok] Provider credentials are valid")
			fmt.Println("[2/4] Checking zone access...")
			if err := p.CheckZoneAccess(ctx, domain); err != nil {
				return err
			}
			fmt.Println("[ok] Provider can access the zone")
			fmt.Println("[3/4] Checking public DNS resolution...")
			if err := dns.EnsureResolvable(ctx, domain, flags.DNSResolver); err != nil {
				return err
			}
			fmt.Println("[ok] Domain resolves in public DNS")
			fmt.Println("[4/4] Optional provider write test...")
			if writeTest {
				if err := dns.CheckPrecursors(ctx, p, domain, flags.DNSResolver, true); err != nil {
					return err
				}
				fmt.Println("[ok] Temporary TXT record create/delete worked")
			} else {
				fmt.Println("[skip] Write test disabled")
			}
			fmt.Println("All precursor checks passed.")
			return nil
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "target domain or wildcard domain")
	cmd.Flags().StringVar(&flags.Provider, "provider", "", "dns provider: godaddy or namecheap")
	cmd.Flags().StringVar(&flags.APIUser, "api-user", "", "provider API user/key id")
	cmd.Flags().StringVar(&flags.APIKey, "api-key", "", "provider API secret/key")
	cmd.Flags().StringVar(&flags.ClientIP, "client-ip", "", "namecheap whitelisted client IP")
	cmd.Flags().StringVar(&flags.DNSResolver, "dns-resolver", "8.8.8.8", "resolver used for prerequisite DNS lookup")
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "overall timeout")
	cmd.Flags().BoolVar(&writeTest, "write-test", false, "create and remove a temporary TXT record")
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("provider")
	rootCmd.AddCommand(cmd)
}
