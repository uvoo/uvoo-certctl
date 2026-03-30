package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func init() {
	var flags providerFlags
	var domain, name, value, recordType string
	var timeout time.Duration
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "delete-record",
		Short: "Delete a DNS record through the provider API",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := withTimeout(timeout)
			defer cancel()
			p, err := providerFromFlags(ctx, flags)
			if err != nil {
				return err
			}
			if err := p.DeleteRecord(ctx, domain, name, strings.ToUpper(recordType), value); err != nil {
				return err
			}
			if jsonOut {
				return printJSON(map[string]any{
					"action": "delete_record",
					"domain": domain,
					"name":   name,
					"type":   strings.ToUpper(recordType),
					"value":  value,
				})
			}
			fmt.Printf("Deleted %s record %s for %s\n", strings.ToUpper(recordType), name, domain)
			return nil
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "zone or domain name")
	cmd.Flags().StringVar(&name, "name", "", "record name or FQDN (use @ for zone apex)")
	cmd.Flags().StringVar(&recordType, "type", "TXT", "record type")
	cmd.Flags().StringVar(&value, "value", "", "record value to delete; leave empty to remove all matching name/type")
	cmd.Flags().StringVar(&flags.Provider, "provider", "", "dns provider: godaddy or namecheap")
	cmd.Flags().StringVar(&flags.APIUser, "api-user", "", "provider API user/key id")
	cmd.Flags().StringVar(&flags.APIKey, "api-key", "", "provider API secret/key")
	cmd.Flags().StringVar(&flags.ClientIP, "client-ip", "", "namecheap whitelisted client IP")
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "overall timeout")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("provider")
	rootCmd.AddCommand(cmd)
}
