package cmd

import (
	"fmt"
	"time"

	"uvoocertctl/internal/ops"
	"uvoocertctl/internal/storage"
	"uvoocertctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var rootID string
	var rootName string
	var name string
	var commonName string
	var days int
	var keyType string

	var parentKeyPassword string
	var keyPassword string
	var storagePassword string

	var org string
	var orgUnit string
	var country string
	var province string
	var locality string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "create-intermediate-ca",
		Short: "Create a private intermediate CA signed by a private root CA",
		Example: `  uvoocertctl create-intermediate-ca \
    --root-name corp-root \
    --name corp-issuing \
    --common-name "Corp Issuing CA" \
    --parent-key-password env:CERTCTL_PARENT_KEY_PASSWORD \
    --key-password env:CERTCTL_KEY_PASSWORD`,
		RunE: func(cmd *cobra.Command, args []string) error {
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
				return fmt.Errorf("root CA password required: %w", err)
			}

			childPassword, err := util.ResolveCryptoPassword(keyPassword, storagePassword)
			if err != nil {
				return fmt.Errorf("intermediate CA password required: %w", err)
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := ops.CreatePrivateIntermediateCA(store, ops.CreatePrivateIntermediateCAParams{
				RootID:              rootID,
				RootName:            rootName,
				DefaultRootName:     rootCfg.DefaultRootCAName,
				Name:                name,
				CommonName:          commonName,
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
			if jsonOut {
				return printJSON(map[string]any{
					"id":          rec.ID,
					"root_ca_id":  rec.RootCAID,
					"name":        rec.Name,
					"common_name": rec.CommonName,
					"generation":  rec.Generation,
					"status":      rec.Status,
					"is_trusted":  rec.IsTrusted,
					"is_issuing":  rec.IsIssuing,
					"key_type":    rec.KeyType,
					"issuer":      rec.Issuer,
					"not_before":  formatTimeValue(rec.NotBefore),
					"not_after":   formatTimeValue(rec.NotAfter),
				})
			}

			fmt.Printf("Created private intermediate CA %s\n", name)
			fmt.Printf("id:         %s\n", rec.ID)
			fmt.Printf("root id:    %s\n", rec.RootCAID)
			fmt.Printf("generation: %d\n", rec.Generation)
			fmt.Printf("status:     %s\n", rec.Status)
			fmt.Printf("commonName: %s\n", rec.CommonName)
			fmt.Printf("keyType:    %s\n", rec.KeyType)
			fmt.Printf("notBefore:  %s\n", rec.NotBefore.Format(time.RFC3339))
			fmt.Printf("notAfter:   %s\n", rec.NotAfter.Format(time.RFC3339))
			return nil
		},
	}

	cmd.Flags().StringVar(&rootID, "root-id", "", "root CA ID used to sign the intermediate")
	cmd.Flags().StringVar(&rootName, "root-name", "", "active root CA logical name used to sign the intermediate")
	cmd.Flags().StringVar(&name, "name", "", "intermediate CA logical name")
	cmd.Flags().StringVar(&commonName, "common-name", "", "intermediate CA common name")
	cmd.Flags().IntVar(&days, "days", 1825, "validity in days")
	cmd.Flags().StringVar(&keyType, "key-type", "ec256", "key type: ec256, ec384, rsa2048, rsa4096, ed25519")

	cmd.Flags().StringVar(&parentKeyPassword, "parent-key-password", "", "password for decrypting the parent root CA key")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "per-intermediate encryption password")
	cmd.Flags().StringVar(&storagePassword, "storage-password", "", "fallback encryption password")

	cmd.Flags().StringVar(&org, "org", "", "organization")
	cmd.Flags().StringVar(&orgUnit, "org-unit", "", "organizational unit")
	cmd.Flags().StringVar(&country, "country", "", "country")
	cmd.Flags().StringVar(&province, "province", "", "province/state")
	cmd.Flags().StringVar(&locality, "locality", "", "locality/city")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("common-name")

	rootCmd.AddCommand(cmd)
}
