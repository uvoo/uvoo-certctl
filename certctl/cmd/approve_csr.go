package cmd

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"certctl/internal/ops"
	"certctl/internal/storage"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var id string
	var note string
	var email string
	var flags providerFlags
	var staging bool
	var timeout time.Duration
	var propagation time.Duration
	var skipChecks bool
	var intermediateID string
	var intermediateName string
	var parentKeyPassword string
	var storagePassword string
	var certType string
	var days int
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "approve-csr",
		Short: "Approve a queued CSR request and issue the certificate",
		Example: `  certctl approve-csr --id <request-id> \
    --provider godaddy --api-user "$GODADDY_API_KEY" --api-key "$GODADDY_API_SECRET"

  certctl approve-csr --id <request-id> \
    --intermediate-name corp-issuing \
    --parent-key-password env:CERTCTL_PARENT_KEY_PASSWORD`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			req, err := store.GetCSRRequestByID(id)
			if err != nil {
				return err
			}
			if req.Status != storage.CSRStatusPending {
				return fmt.Errorf("csr request %s is not pending", req.ID)
			}

			switch req.Kind {
			case storage.CertKindPublic:
				rec, err := approvePublicCSRRequest(store, req, approvePublicCSRConfig{
					ProviderFlags: flags,
					Email:         firstNonEmpty(strings.TrimSpace(email), req.RequesterEmail),
					Staging:       staging,
					Timeout:       timeout,
					Propagation:   propagation,
					SkipChecks:    skipChecks,
					DecisionNote:  note,
				})
				if err != nil {
					return err
				}
				if jsonOut {
					return printJSON(map[string]any{
						"request_id":         req.ID,
						"status":             storage.CSRStatusIssued,
						"kind":               req.Kind,
						"issued_cert_id":     rec.ID,
						"common_name":        rec.CommonName,
						"sans_csv":           rec.SANsCSV,
						"provider":           rec.Provider,
						"not_before":         formatTimeValue(rec.NotBefore),
						"not_after":          formatTimeValue(rec.NotAfter),
						"private_key_stored": privateKeyStored(rec.KeyPEM),
					})
				}
				fmt.Printf("Approved CSR request %s\n", req.ID)
				printKV("issued_cert_id", rec.ID)
				printKV("common_name", rec.CommonName)
				printKV("sans", rec.SANsCSV)
				return nil

			case storage.CertKindPrivate:
				parentKeyPassword, err := util.ResolveSecretValue(parentKeyPassword, "CERTCTL_PARENT_KEY_PASSWORD")
				if err != nil {
					return err
				}
				storagePassword, err = util.ResolveSecretValue(storagePassword, "CERTCTL_STORAGE_PASSWORD")
				if err != nil {
					return err
				}

				rec, err := approvePrivateCSRRequest(store, req, approvePrivateCSRConfig{
					IntermediateID:   intermediateID,
					IntermediateName: intermediateName,
					ParentPassword:   parentKeyPassword,
					StoragePassword:  storagePassword,
					CertType:         certType,
					Days:             days,
					DecisionNote:     note,
				})
				if err != nil {
					return err
				}
				if jsonOut {
					return printJSON(map[string]any{
						"request_id":         req.ID,
						"status":             storage.CSRStatusIssued,
						"kind":               req.Kind,
						"issued_cert_id":     rec.ID,
						"common_name":        rec.CommonName,
						"sans_csv":           rec.SANsCSV,
						"cert_type":          rec.CertType,
						"intermediate_ca_id": rec.IntermediateCAID,
						"not_before":         formatTimeValue(rec.NotBefore),
						"not_after":          formatTimeValue(rec.NotAfter),
						"private_key_stored": privateKeyStored(rec.KeyPEM),
					})
				}
				fmt.Printf("Approved CSR request %s\n", req.ID)
				printKV("issued_cert_id", rec.ID)
				printKV("common_name", rec.CommonName)
				printKV("sans", rec.SANsCSV)
				return nil
			}

			return fmt.Errorf("unsupported csr kind: %s", req.Kind)
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "csr request id")
	cmd.Flags().StringVar(&note, "note", "", "optional approval note")
	cmd.Flags().StringVar(&email, "email", "", "optional ACME account email override for public requests")
	cmd.Flags().StringVar(&flags.Provider, "provider", "", "dns provider for public requests: godaddy or namecheap")
	cmd.Flags().StringVar(&flags.APIUser, "api-user", "", "provider API user/key id for public requests")
	cmd.Flags().StringVar(&flags.APIKey, "api-key", "", "provider API secret/key for public requests")
	cmd.Flags().StringVar(&flags.ClientIP, "client-ip", "", "namecheap whitelisted client IP for public requests")
	cmd.Flags().StringVar(&flags.DNSResolver, "dns-resolver", "8.8.8.8", "resolver used for public precursor checks")
	cmd.Flags().BoolVar(&staging, "staging", false, "use Let's Encrypt staging for public requests")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "overall ACME timeout for public requests")
	cmd.Flags().DurationVar(&propagation, "propagation-timeout", 30*time.Minute, "DNS propagation timeout for public requests")
	cmd.Flags().BoolVar(&skipChecks, "skip-checks", false, "skip precursor checks for public requests")
	cmd.Flags().StringVar(&intermediateID, "intermediate-id", "", "private intermediate CA id override for private requests")
	cmd.Flags().StringVar(&intermediateName, "intermediate-name", "", "private intermediate CA logical name override for private requests")
	cmd.Flags().StringVar(&parentKeyPassword, "parent-key-password", "", "password for decrypting the issuing intermediate CA key")
	cmd.Flags().StringVar(&storagePassword, "storage-password", "", "fallback encryption password for decrypting the issuing intermediate CA key")
	cmd.Flags().StringVar(&certType, "cert-type", "", "private cert type override: server, client, or server_client")
	cmd.Flags().IntVar(&days, "days", 0, "private certificate validity override in days")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("parent-key-password")
	_ = cmd.MarkFlagRequired("intermediate-name")
	rootCmd.AddCommand(cmd)
}

type approvePublicCSRConfig struct {
	ProviderFlags providerFlags
	Email         string
	Staging       bool
	Timeout       time.Duration
	Propagation   time.Duration
	SkipChecks    bool
	DecisionNote  string
}

func approvePublicCSRRequest(store *storage.Store, req storage.CSRRequest, cfg approvePublicCSRConfig) (storage.PublicCert, error) {
	result, err := ops.ApprovePublicCSRRequest(store, ops.ApprovePublicCSRParams{
		Request: req,
		Provider: ops.ProviderConfig{
			Provider:    cfg.ProviderFlags.Provider,
			APIUser:     cfg.ProviderFlags.APIUser,
			APIKey:      cfg.ProviderFlags.APIKey,
			ClientIP:    cfg.ProviderFlags.ClientIP,
			DNSResolver: cfg.ProviderFlags.DNSResolver,
			HTTPTimeout: rootCfg.HTTPTimeout,
		},
		Email:        cfg.Email,
		Staging:      cfg.Staging,
		Timeout:      cfg.Timeout,
		Propagation:  cfg.Propagation,
		SkipChecks:   cfg.SkipChecks,
		DecisionNote: cfg.DecisionNote,
	})
	if err != nil {
		return storage.PublicCert{}, err
	}
	printSANConflicts(result.Warnings)
	return result.Record, nil
}

type approvePrivateCSRConfig struct {
	IntermediateID   string
	IntermediateName string
	ParentPassword   string
	StoragePassword  string
	CertType         string
	Days             int
	DecisionNote     string
}

func approvePrivateCSRRequest(store *storage.Store, req storage.CSRRequest, cfg approvePrivateCSRConfig) (storage.PrivateCert, error) {
	result, err := ops.ApprovePrivateCSRRequest(store, ops.ApprovePrivateCSRParams{
		Request:             req,
		IntermediateID:      cfg.IntermediateID,
		IntermediateName:    cfg.IntermediateName,
		DefaultIntermediate: rootCfg.DefaultIntermediateName,
		ParentPassword:      cfg.ParentPassword,
		StoragePassword:     cfg.StoragePassword,
		CertType:            cfg.CertType,
		Days:                cfg.Days,
		DecisionNote:        cfg.DecisionNote,
	})
	if err != nil {
		return storage.PrivateCert{}, err
	}
	printSANConflicts(result.Warnings)
	return result.Record, nil
}

func publicCSRNames(csr *x509.CertificateRequest) []string {
	return ops.PublicCSRNames(csr)
}

func validatePublicCSR(csr *x509.CertificateRequest) error {
	return ops.ValidatePublicCSR(csr)
}

func firstNonEmpty(values ...string) string {
	return ops.FirstNonEmpty(values...)
}
