package cmd

import (
	"fmt"
	"time"

	"certctl/internal/ops"
	"certctl/internal/storage"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var intermediateID string
	var intermediateName string
	var commonName string
	var domains []string
	var sans []string
	var certType string
	var days int
	var keyType string

	var parentKeyPassword string
	var parentPasswordAlias string
	var keyPassword string
	var storagePassword string

	var org string
	var orgUnit string
	var country string
	var province string
	var locality string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "issue-private-cert",
		Short: "Issue a private leaf certificate from an intermediate CA",
		Example: `  certctl issue-private-cert \
    --intermediate-name corp-issuing \
    --common-name api.internal.example \
    --domain api.internal.example \
    --san api \
    --parent-key-password env:CERTCTL_PARENT_KEY_PASSWORD \
    --key-password env:CERTCTL_KEY_PASSWORD \
    --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if parentKeyPassword == "" && parentPasswordAlias != "" {
				parentKeyPassword = parentPasswordAlias
			}
			parentKeyPassword, err := util.ResolveSecretValue(parentKeyPassword, "CERTCTL_PARENT_KEY_PASSWORD")
			if err != nil {
				return err
			}
			keyPassword, err = util.ResolveSecretValue(keyPassword, "CERTCTL_KEY_PASSWORD")
			if err != nil {
				return err
			}
			storagePassword, err = util.ResolveSecretValue(storagePassword, "CERTCTL_STORAGE_PASSWORD")
			if err != nil {
				return err
			}

			issuerPassword, err := util.ResolveCryptoPassword(parentKeyPassword, storagePassword)
			if err != nil {
				return fmt.Errorf("intermediate CA password required: %w", err)
			}

			childPassword, err := util.ResolveCryptoPassword(keyPassword, storagePassword)
			if err != nil {
				return fmt.Errorf("leaf certificate password required: %w", err)
			}

			if issuerPassword != "" {
				if err := util.IsPasswordComplex(issuerPassword); err != nil {
					return fmt.Errorf("invalid issuer-password: %w", err)
				}
			}
			if childPassword != "" {
				if err := util.IsPasswordComplex(childPassword); err != nil {
					return fmt.Errorf("invalid child-password: %w", err)
				}
			}

			allSANs := ops.NormalizePrivateCertSANs(commonName, append(append([]string{}, domains...), sans...))
			if len(allSANs) == 0 {
				return fmt.Errorf("at least one domain or common name is required")
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			result, err := ops.IssuePrivateCert(store, ops.IssuePrivateCertParams{
				IntermediateID:      intermediateID,
				IntermediateName:    intermediateName,
				DefaultIntermediate: rootCfg.DefaultIntermediateName,
				CommonName:          commonName,
				SANs:                allSANs,
				CertType:            certType,
				Days:                days,
				KeyType:             keyType,
				IssuerPassword:      issuerPassword,
				ChildCryptoPassword: childPassword,
				Org:                 org,
				OrgUnit:             orgUnit,
				Country:             country,
				Province:            province,
				Locality:            locality,
			})
			if err != nil {
				return err
			}
			printSANConflicts(result.Warnings)
			rec := result.Record
			if jsonOut {
				return printJSON(map[string]any{
					"id":                 rec.ID,
					"intermediate_ca_id": rec.IntermediateCAID,
					"common_name":        rec.CommonName,
					"sans_csv":           rec.SANsCSV,
					"cert_type":          rec.CertType,
					"key_type":           rec.KeyType,
					"issuer":             rec.Issuer,
					"status":             rec.Status,
					"not_before":         formatTimeValue(rec.NotBefore),
					"not_after":          formatTimeValue(rec.NotAfter),
				})
			}

			fmt.Printf("Issued private certificate %s\n", commonName)
			fmt.Printf("id:              %s\n", rec.ID)
			fmt.Printf("intermediate id: %s\n", rec.IntermediateCAID)
			fmt.Printf("status:          %s\n", rec.Status)
			fmt.Printf("commonName:      %s\n", rec.CommonName)
			fmt.Printf("sans:         %s\n", rec.SANsCSV)
			fmt.Printf("certType:        %s\n", rec.CertType)
			fmt.Printf("keyType:         %s\n", rec.KeyType)
			fmt.Printf("notBefore:       %s\n", rec.NotBefore.Format(time.RFC3339))
			fmt.Printf("notAfter:        %s\n", rec.NotAfter.Format(time.RFC3339))

			return nil
		},
	}

	cmd.Flags().StringVar(&intermediateID, "intermediate-id", "", "intermediate CA ID used to sign the certificate")
	cmd.Flags().StringVar(&intermediateName, "intermediate-name", "", "active intermediate CA logical name used to sign the certificate")
	cmd.Flags().StringVar(&commonName, "common-name", "", "certificate common name")
	cmd.Flags().StringSliceVar(&domains, "domain", nil, "certificate DNS names or IP SANs; may be repeated or comma-separated")
	cmd.Flags().StringSliceVar(&sans, "san", nil, "alias for --domain; additional SANs")
	cmd.Flags().StringVar(&certType, "cert-type", "server", "certificate type: server, client, or server_client")
	cmd.Flags().IntVar(&days, "days", 825, "validity in days")
	cmd.Flags().StringVar(&keyType, "key-type", "ec256", "key type: ec256, ec384, rsa2048, rsa4096, ed25519")

	cmd.Flags().StringVar(&parentKeyPassword, "parent-key-password", "", "password for decrypting the parent intermediate CA key")
	cmd.Flags().StringVar(&parentPasswordAlias, "parent-password", "", "alias for --parent-key-password")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "per-certificate encryption password")
	cmd.Flags().StringVar(&storagePassword, "storage-password", "", "fallback encryption password")

	cmd.Flags().StringVar(&org, "org", "", "organization")
	cmd.Flags().StringVar(&orgUnit, "org-unit", "", "organizational unit")
	cmd.Flags().StringVar(&country, "country", "", "country")
	cmd.Flags().StringVar(&province, "province", "", "province/state")
	cmd.Flags().StringVar(&locality, "locality", "", "locality/city")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")

	_ = cmd.MarkFlagRequired("common-name")

	rootCmd.AddCommand(cmd)
}
