package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"certctl/internal/cli"
	"certctl/internal/privateca"
	"certctl/internal/storage"
	"certctl/internal/util"

	"github.com/fullsailor/pkcs7"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

func init() {
	var commonName string
	var outDir string
	var keyPassword string
	var storagePassword string
	var format string
	var exportPassword string
	var includeRoot bool

	cmd := &cobra.Command{
		Use:   "export-private-cert",
		Short: "Decrypt and export a stored private certificate and key",
		RunE: func(cmd *cobra.Command, args []string) error {
			cryptoPassword, err := util.ResolveCryptoPassword(keyPassword, storagePassword)
			if err != nil {
				return err
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := store.GetPrivateCertByName(commonName)
			if err != nil {
				return fmt.Errorf("no private certificate found for common name: %s", commonName)
			}

			certPEM, err := cli.Decrypt(rec.CertPEM, cryptoPassword)
			if err != nil {
				return err
			}
			keyPEM, err := cli.Decrypt(rec.KeyPEM, cryptoPassword)
			if err != nil {
				return err
			}

			if outDir == "" {
				outDir = "."
			}
			if err := os.MkdirAll(outDir, 0755); err != nil {
				return err
			}

			base := sanitizeFileBase(rec.CommonName)

			switch strings.ToLower(strings.TrimSpace(format)) {
			case "", "pem":
				return exportPEM(outDir, base, certPEM, keyPEM)

			case "der":
				return exportDER(outDir, base, certPEM, keyPEM)

			case "pkcs12", "p12":
				if strings.TrimSpace(exportPassword) == "" {
					return fmt.Errorf("--export-password is required for pkcs12")
				}
				return exportPKCS12(outDir, base, rec.CommonName, certPEM, keyPEM, exportPassword)

			case "pkcs7", "p7b":
				return exportPKCS7(store, outDir, base, rec, cryptoPassword, includeRoot)

			default:
				return fmt.Errorf("unsupported --format %q (supported: pem, der, pkcs12, pkcs7)", format)
			}
		},
	}

	cmd.Flags().StringVar(&commonName, "common-name", "", "common name or SAN to find the private certificate")
	cmd.Flags().StringVar(&outDir, "out-dir", ".", "directory to write exported files")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "per-certificate encryption password")
	cmd.Flags().StringVar(&storagePassword, "storage-password", "", "fallback encryption password")
	cmd.Flags().StringVar(&format, "format", "pem", "export format: pem, der, pkcs12, pkcs7")
	cmd.Flags().StringVar(&exportPassword, "export-password", "", "password for pkcs12 export")
	cmd.Flags().BoolVar(&includeRoot, "include-root", false, "include root CA in pkcs7 export")

	_ = cmd.MarkFlagRequired("common-name")

	rootCmd.AddCommand(cmd)
}

func exportPEM(outDir, base string, certPEM, keyPEM []byte) error {
	certPath := filepath.Join(outDir, base+".cert.pem")
	keyPath := filepath.Join(outDir, base+".key.pem")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}

	fmt.Printf("Exported certificate: %s\n", certPath)
	fmt.Printf("Exported private key: %s\n", keyPath)
	return nil
}

func exportDER(outDir, base string, certPEM, keyPEM []byte) error {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("invalid certificate PEM")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("invalid private key PEM")
	}

	certPath := filepath.Join(outDir, base+".cert.der")
	keyPath := filepath.Join(outDir, base+".key.der")

	if err := os.WriteFile(certPath, certBlock.Bytes, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyBlock.Bytes, 0600); err != nil {
		return err
	}

	fmt.Printf("Exported certificate: %s\n", certPath)
	fmt.Printf("Exported private key: %s\n", keyPath)
	return nil
}

func exportPKCS12(outDir, base, friendlyName string, certPEM, keyPEM []byte, exportPassword string) error {
	cert, err := privateca.ParseCertPEM(certPEM)
	if err != nil {
		return err
	}

	key, err := privateca.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return err
	}

	pfxBytes, err := pkcs12.Modern.Encode(key, cert, nil, exportPassword)
	if err != nil {
		return err
	}

	outPath := filepath.Join(outDir, base+".p12")
	if err := os.WriteFile(outPath, pfxBytes, 0600); err != nil {
		return err
	}

	fmt.Printf("Exported PKCS#12 bundle: %s\n", outPath)
	_ = friendlyName
	return nil
}

func decryptAndParseCert(enc []byte, password string) (*x509.Certificate, error) {
	pemBytes, err := cli.Decrypt(enc, password)
	if err != nil {
		return nil, err
	}
	return privateca.ParseCertPEM(pemBytes)
}

func exportPKCS7(store *storage.Store, outDir, base string, rec storage.PrivateCert, cryptoPassword string, includeRoot bool) error {
	leafCert, err := decryptAndParseCert(rec.CertPEM, cryptoPassword)
	if err != nil {
		return err
	}

	icaRec, err := store.GetPrivateIntermediateCAByID(rec.IntermediateCAID)
	if err != nil {
		return err
	}
	icaCert, err := decryptAndParseCert(icaRec.CertPEM, cryptoPassword)
	if err != nil {
		return err
	}

	sd, err := pkcs7.NewSignedData([]byte{})
	if err != nil {
		return err
	}

	sd.AddCertificate(leafCert)
	sd.AddCertificate(icaCert)

	if includeRoot && icaRec.RootCAID != "" {
		rootRec, err := store.GetPrivateRootCAByID(icaRec.RootCAID)
		if err != nil {
			return err
		}
		rootCert, err := decryptAndParseCert(rootRec.CertPEM, cryptoPassword)
		if err != nil {
			return err
		}
		sd.AddCertificate(rootCert)
	}

	p7Bytes, err := sd.Finish()
	if err != nil {
		return err
	}

	outPath := filepath.Join(outDir, base+".p7b")
	if err := os.WriteFile(outPath, p7Bytes, 0644); err != nil {
		return err
	}

	fmt.Printf("Exported PKCS#7 bundle: %s\n", outPath)
	return nil
}

func sanitizeFileBase(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "*", "wildcard")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

// quiet parse guard if needed by older tooling
var _ = x509.MarshalPKCS1PublicKey
