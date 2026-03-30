package cmd

import (
	"fmt"
	"time"

	"certctl/internal/cli"
	"certctl/internal/privateca"
	"certctl/internal/storage"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var name, commonName string
	var days int
	var keyType string
	var keyPassword, storagePassword string
	var org, orgUnit, country, province, locality string

	cmd := &cobra.Command{
		Use:   "create-root-ca",
		Short: "Create a private root CA and store it encrypted",
		RunE: func(cmd *cobra.Command, args []string) error {
			cryptoPassword, err := util.ResolveCryptoPassword(keyPassword, storagePassword)
			if err != nil {
				return err
			}

			res, _, _, err := privateca.CreateRootCA(privateca.CreateRootOptions{
				CommonName: commonName,
				KeyType:    keyType,
				Days:       days,
				Org:        org,
				OrgUnit:    orgUnit,
				Country:    country,
				Province:   province,
				Locality:   locality,
			})
			if err != nil {
				return err
			}

			plainCert := res.CertPEM
			encKey, err := cli.Encrypt(res.KeyPEM, cryptoPassword)
			if err != nil {
				return err
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec := storage.PrivateRootCA{
				ID:         util.NewID(),
				Name:       name,
				CommonName: commonName,
				KeyType:    keyType,
				CertPEM:    plainCert,
				KeyPEM:     encKey,
				Issuer:     res.Issuer,
				NotBefore:  res.NotBefore,
				NotAfter:   res.NotAfter,
			}

			if err := store.UpsertPrivateRootCA(rec); err != nil {
				return err
			}

			fmt.Printf("Created private root CA %s\n", name)
			fmt.Printf("id:         %s\n", rec.ID)
			fmt.Printf("commonName: %s\n", rec.CommonName)
			fmt.Printf("keyType:    %s\n", rec.KeyType)
			fmt.Printf("notBefore:  %s\n", rec.NotBefore.Format(time.RFC3339))
			fmt.Printf("notAfter:   %s\n", rec.NotAfter.Format(time.RFC3339))
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "unique root CA name")
	cmd.Flags().StringVar(&commonName, "common-name", "", "root CA common name")
	cmd.Flags().IntVar(&days, "days", 3650, "validity in days")
	cmd.Flags().StringVar(&keyType, "key-type", "ec256", "key type: ec256, ec384, rsa2048, rsa4096, ed25519")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "per-CA encryption password")
	cmd.Flags().StringVar(&storagePassword, "storage-password", "", "fallback encryption password")
	cmd.Flags().StringVar(&org, "org", "", "organization")
	cmd.Flags().StringVar(&orgUnit, "org-unit", "", "organizational unit")
	cmd.Flags().StringVar(&country, "country", "", "country")
	cmd.Flags().StringVar(&province, "province", "", "province/state")
	cmd.Flags().StringVar(&locality, "locality", "", "locality/city")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("common-name")

	rootCmd.AddCommand(cmd)
}
