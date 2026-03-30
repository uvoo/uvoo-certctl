package cmd

import (
	"fmt"
	"strings"
	"time"

	"certctl/internal/cli"
	"certctl/internal/privateca"
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

	cmd := &cobra.Command{
		Use:   "issue-private-cert",
		Short: "Issue a private leaf certificate from an intermediate CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			if parentKeyPassword == "" && parentPasswordAlias != "" {
				parentKeyPassword = parentPasswordAlias
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

			allSANs := normalizePrivateCertSANs(commonName, append(append([]string{}, domains...), sans...))
			if len(allSANs) == 0 {
				return fmt.Errorf("at least one domain or common name is required")
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			var icaRec storage.PrivateIntermediateCA
			switch {
			case strings.TrimSpace(intermediateID) != "":
				icaRec, err = store.GetPrivateIntermediateCAByID(intermediateID)
				if err != nil {
					return fmt.Errorf("failed to load intermediate CA %q: %w", intermediateID, err)
				}
			case strings.TrimSpace(intermediateName) != "":
				icaRec, err = store.GetIssuingPrivateIntermediateCAByName(intermediateName)
				if err != nil {
					return fmt.Errorf("failed to load issuing intermediate CA %q: %w", intermediateName, err)
				}
			case strings.TrimSpace(rootCfg.DefaultIntermediateName) != "":
				icaRec, err = store.GetIssuingPrivateIntermediateCAByName(rootCfg.DefaultIntermediateName)
				if err != nil {
					return fmt.Errorf("failed to load issuing intermediate CA %q: %w", rootCfg.DefaultIntermediateName, err)
				}
			default:
				return fmt.Errorf("one of --intermediate-id, --intermediate-name, or --default-intermediate-ca is required")
			}
			if icaRec.Status != storage.StatusActive || !icaRec.IsIssuing {
				return fmt.Errorf("intermediate CA %q is not active for issuance", icaRec.ID)
			}

			if err := warnPrivateSANConflicts(store, commonName, allSANs); err != nil {
				return err
			}

			icaCertPEM := icaRec.CertPEM

			icaKeyPEM, err := cli.Decrypt(icaRec.KeyPEM, issuerPassword)
			if err != nil {
				return fmt.Errorf("failed to decrypt intermediate CA private key: %w", err)
			}

			icaCert, err := privateca.ParseCertPEM(icaCertPEM)
			if err != nil {
				return fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
			}

			icaKey, err := privateca.ParsePrivateKeyPEM(icaKeyPEM)
			if err != nil {
				return fmt.Errorf("failed to parse intermediate CA private key: %w", err)
			}

			res, _, err := privateca.IssueLeaf(icaCert, icaKey, privateca.IssueLeafOptions{
				CommonName: commonName,
				SANs:       allSANs,
				CertType:   certType,
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
			encKey, err := cli.Encrypt(res.KeyPEM, childPassword)
			if err != nil {
				return err
			}

			rec := storage.PrivateCert{
				ID:               util.NewID(),
				IntermediateCAID: icaRec.ID,
				CommonName:       commonName,
				SANsCSV:          strings.Join(allSANs, ","),
				CertType:         certType,
				KeyType:          keyType,
				CertPEM:          plainCert,
				KeyPEM:           encKey,
				Issuer:           res.Issuer,
				Status:           storage.StatusActive,
				NotBefore:        res.NotBefore,
				NotAfter:         res.NotAfter,
			}

			if err := store.UpsertPrivateCert(rec); err != nil {
				return err
			}
			rec, err = store.GetPrivateCertByID(rec.ID)
			if err != nil {
				return err
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

	_ = cmd.MarkFlagRequired("common-name")

	rootCmd.AddCommand(cmd)
}

func normalizePrivateCertSANs(commonName string, sans []string) []string {
	seen := map[string]struct{}{}
	var out []string

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	add(commonName)

	for _, item := range sans {
		for part := range strings.SplitSeq(item, ",") {
			add(part)
		}
	}

	return out
}
