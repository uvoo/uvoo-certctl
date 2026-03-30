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
	var rootID string
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

	cmd := &cobra.Command{
		Use:   "create-intermediate-ca",
		Short: "Create a private intermediate CA signed by a private root CA",
		RunE: func(cmd *cobra.Command, args []string) error {
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

			rootRec, err := store.GetPrivateRootCAByID(rootID)
			if err != nil {
				return fmt.Errorf("failed to load root CA %q: %w", rootID, err)
			}

			rootCertPEM := rootRec.CertPEM

			rootKeyPEM, err := cli.Decrypt(rootRec.KeyPEM, issuerPassword)
			if err != nil {
				return fmt.Errorf("failed to decrypt root CA private key: %w", err)
			}

			rootCert, err := privateca.ParseCertPEM(rootCertPEM)
			if err != nil {
				return fmt.Errorf("failed to parse root CA certificate: %w", err)
			}

			rootKey, err := privateca.ParsePrivateKeyPEM(rootKeyPEM)
			if err != nil {
				return fmt.Errorf("failed to parse root CA private key: %w", err)
			}

			res, _, _, err := privateca.CreateIntermediateCA(rootCert, rootKey, privateca.CreateIntermediateOptions{
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

			/*
				encCert, err := cli.Encrypt(res.CertPEM, childPassword)
				if err != nil {
					return err
				}
			*/
			plainCert := res.CertPEM
			encKey, err := cli.Encrypt(res.KeyPEM, childPassword)
			if err != nil {
				return err
			}

			rec := storage.PrivateIntermediateCA{
				ID:         util.NewID(),
				RootCAID:   rootRec.ID,
				Name:       name,
				CommonName: commonName,
				KeyType:    keyType,
				CertPEM:    plainCert,
				KeyPEM:     encKey,
				Issuer:     res.Issuer,
				NotBefore:  res.NotBefore,
				NotAfter:   res.NotAfter,
			}

			if err := store.UpsertPrivateIntermediateCA(rec); err != nil {
				return err
			}

			fmt.Printf("Created private intermediate CA %s\n", name)
			fmt.Printf("id:         %s\n", rec.ID)
			fmt.Printf("root id:    %s\n", rec.RootCAID)
			fmt.Printf("commonName: %s\n", rec.CommonName)
			fmt.Printf("keyType:    %s\n", rec.KeyType)
			fmt.Printf("notBefore:  %s\n", rec.NotBefore.Format(time.RFC3339))
			fmt.Printf("notAfter:   %s\n", rec.NotAfter.Format(time.RFC3339))
			return nil
		},
	}

	cmd.Flags().StringVar(&rootID, "root-id", "", "root CA ID used to sign the intermediate")
	cmd.Flags().StringVar(&name, "name", "", "unique intermediate CA name")
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

	_ = cmd.MarkFlagRequired("root-id")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("common-name")

	rootCmd.AddCommand(cmd)
}
