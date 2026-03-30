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
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "export-private-cert",
		Short: "Decrypt and export a stored private certificate and key",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := store.GetPrivateCertByNameOrSAN(commonName)
			if err != nil {
				return fmt.Errorf("no private certificate found for common name: %s", commonName)
			}

			if outDir == "" {
				outDir = "."
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}

			base := sanitizeFileBase(rec.CommonName)
			format = strings.ToLower(strings.TrimSpace(format))

			certPEM := rec.CertPEM

			switch format {
			case "pkcs7", "p7b":
				// PKCS#7 export does not need the private key.
				outPath, err := exportPKCS7(store, outDir, base, rec, includeRoot)
				if err != nil {
					return err
				}
				if jsonOut {
					return printJSON(map[string]any{"format": "pkcs7", "path": outPath, "common_name": rec.CommonName})
				}
				return nil

			case "", "pem", "der", "pkcs12", "p12":
				// These formats need the private key, so only resolve/decrypt here.
				keyPassword, err = util.ResolveSecretValue(keyPassword, "CERTCTL_KEY_PASSWORD")
				if err != nil {
					return err
				}
				storagePassword, err = util.ResolveSecretValue(storagePassword, "CERTCTL_STORAGE_PASSWORD")
				if err != nil {
					return err
				}
				cryptoPassword, err := util.ResolveCryptoPassword(keyPassword, storagePassword)
				if err != nil {
					return err
				}

				keyPEM, err := cli.Decrypt(rec.KeyPEM, cryptoPassword)
				if err != nil {
					return err
				}

				switch format {
				case "", "pem":
					certPath, keyPath, err := exportPEM(outDir, base, certPEM, keyPEM)
					if err != nil {
						return err
					}
					if jsonOut {
						return printJSON(map[string]any{"format": "pem", "certificate_path": certPath, "private_key_path": keyPath, "common_name": rec.CommonName})
					}
					return nil

				case "der":
					certPath, keyPath, err := exportDER(outDir, base, certPEM, keyPEM)
					if err != nil {
						return err
					}
					if jsonOut {
						return printJSON(map[string]any{"format": "der", "certificate_path": certPath, "private_key_path": keyPath, "common_name": rec.CommonName})
					}
					return nil

				case "pkcs12", "p12":
					if strings.TrimSpace(exportPassword) == "" {
						return fmt.Errorf("--export-password is required for pkcs12")
					}
					outPath, err := exportPKCS12(outDir, base, rec.CommonName, certPEM, keyPEM, exportPassword)
					if err != nil {
						return err
					}
					if jsonOut {
						return printJSON(map[string]any{"format": "pkcs12", "path": outPath, "common_name": rec.CommonName})
					}
					return nil
				}

			default:
				return fmt.Errorf("unsupported --format %q (supported: pem, der, pkcs12, pkcs7)", format)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&commonName, "common-name", "", "common name or SAN to find the private certificate")
	cmd.Flags().StringVar(&outDir, "out-dir", ".", "directory to write exported files")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "per-certificate encryption password")
	cmd.Flags().StringVar(&storagePassword, "storage-password", "", "fallback encryption password")
	cmd.Flags().StringVar(&format, "format", "pem", "export format: pem, der, pkcs12, pkcs7")
	cmd.Flags().StringVar(&exportPassword, "export-password", "", "password for pkcs12 export")
	cmd.Flags().BoolVar(&includeRoot, "include-root", false, "include root CA in pkcs7 export")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")

	_ = cmd.MarkFlagRequired("common-name")

	rootCmd.AddCommand(cmd)
}

func exportPEM(outDir, base string, certPEM, keyPEM []byte) (string, string, error) {
	certPath := filepath.Join(outDir, base+".cert.pem")
	keyPath := filepath.Join(outDir, base+".key.pem")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", "", err
	}

	fmt.Printf("Exported certificate: %s\n", certPath)
	fmt.Printf("Exported private key: %s\n", keyPath)
	return certPath, keyPath, nil
}

func exportDER(outDir, base string, certPEM, keyPEM []byte) (string, string, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return "", "", fmt.Errorf("invalid certificate PEM")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return "", "", fmt.Errorf("invalid private key PEM")
	}

	certPath := filepath.Join(outDir, base+".cert.der")
	keyPath := filepath.Join(outDir, base+".key.der")

	if err := os.WriteFile(certPath, certBlock.Bytes, 0644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyBlock.Bytes, 0600); err != nil {
		return "", "", err
	}

	fmt.Printf("Exported certificate: %s\n", certPath)
	fmt.Printf("Exported private key: %s\n", keyPath)
	return certPath, keyPath, nil
}

func exportPKCS12(outDir, base, friendlyName string, certPEM, keyPEM []byte, exportPassword string) (string, error) {
	cert, err := privateca.ParseCertPEM(certPEM)
	if err != nil {
		return "", err
	}

	key, err := privateca.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return "", err
	}

	pfxBytes, err := pkcs12.Modern.Encode(key, cert, nil, exportPassword)
	if err != nil {
		return "", err
	}

	outPath := filepath.Join(outDir, base+".p12")
	if err := os.WriteFile(outPath, pfxBytes, 0600); err != nil {
		return "", err
	}

	fmt.Printf("Exported PKCS#12 bundle: %s\n", outPath)
	_ = friendlyName
	return outPath, nil
}

func decryptAndParseCert(enc []byte, password string) (*x509.Certificate, error) {
	pemBytes, err := cli.Decrypt(enc, password)
	if err != nil {
		return nil, err
	}
	return privateca.ParseCertPEM(pemBytes)
}

func exportPKCS7(store *storage.Store, outDir, base string, rec storage.PrivateCert, includeRoot bool) (string, error) {
	leafCert, err := privateca.ParseCertPEM(rec.CertPEM)
	if err != nil {
		return "", err
	}

	icaRec, err := store.GetPrivateIntermediateCAByID(rec.IntermediateCAID)
	if err != nil {
		return "", err
	}
	icaCert, err := privateca.ParseCertPEM(icaRec.CertPEM)
	if err != nil {
		return "", err
	}

	sd, err := pkcs7.NewSignedData([]byte{})
	if err != nil {
		return "", err
	}

	sd.AddCertificate(leafCert)
	sd.AddCertificate(icaCert)

	if includeRoot && icaRec.RootCAID != "" {
		rootRec, err := store.GetPrivateRootCAByID(icaRec.RootCAID)
		if err != nil {
			return "", err
		}
		rootCert, err := privateca.ParseCertPEM(rootRec.CertPEM)
		if err != nil {
			return "", err
		}
		sd.AddCertificate(rootCert)
	}

	p7Bytes, err := sd.Finish()
	if err != nil {
		return "", err
	}

	outPath := filepath.Join(outDir, base+".p7b")
	if err := os.WriteFile(outPath, p7Bytes, 0644); err != nil {
		return "", err
	}

	fmt.Printf("Exported PKCS#7 bundle: %s\n", outPath)
	return outPath, nil
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
