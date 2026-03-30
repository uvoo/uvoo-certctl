package cmd

import (
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"certctl/internal/acme"
	"certctl/internal/cli"
	"certctl/internal/dns"
	"certctl/internal/privateca"
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
	csr, err := parseCSRRequest(req)
	if err != nil {
		return storage.PublicCert{}, err
	}
	if err := validatePublicCSR(csr); err != nil {
		return storage.PublicCert{}, err
	}

	ctx, cancel := withTimeout(cfg.Timeout)
	defer cancel()

	provider, err := providerFromFlags(ctx, cfg.ProviderFlags)
	if err != nil {
		return storage.PublicCert{}, err
	}

	names := publicCSRNames(csr)
	if !cfg.SkipChecks {
		for _, name := range names {
			if err := dns.CheckPrecursors(ctx, provider, name, cfg.ProviderFlags.DNSResolver, false); err != nil {
				return storage.PublicCert{}, err
			}
		}
	}

	if err := warnPublicSANConflicts(store, req.CommonName, append([]string{req.CommonName}, names...)); err != nil {
		return storage.PublicCert{}, err
	}

	resource, err := acme.IssueForCSR(ctx, acme.IssueForCSROptions{
		Email:       cfg.Email,
		CSR:         csr,
		Provider:    cfg.ProviderFlags.Provider,
		APIUser:     cfg.ProviderFlags.APIUser,
		APIKey:      cfg.ProviderFlags.APIKey,
		ClientIP:    cfg.ProviderFlags.ClientIP,
		Timeout:     cfg.Timeout,
		UseStaging:  cfg.Staging,
		Propagation: cfg.Propagation,
	})
	if err != nil {
		return storage.PublicCert{}, err
	}

	_, sansCSV, sansHash := storage.NormalizeSANs(publicCSRNames(csr))
	issuer, notBefore, notAfter, err := storage.ParseCertMetadata(resource.Certificate)
	if err != nil {
		return storage.PublicCert{}, err
	}

	rec := storage.PublicCert{
		ID:         util.NewID(),
		CommonName: req.CommonName,
		SANsCSV:    sansCSV,
		SANsHash:   sansHash,
		CertPEM:    resource.Certificate,
		KeyPEM:     nil,
		Provider:   cfg.ProviderFlags.Provider,
		Email:      cfg.Email,
		Issuer:     issuer,
		NotBefore:  notBefore,
		NotAfter:   notAfter,
	}
	if err := store.Upsert(rec); err != nil {
		return storage.PublicCert{}, err
	}
	rec, err = store.GetByCommonName(req.CommonName)
	if err != nil {
		return storage.PublicCert{}, err
	}
	if err := store.MarkCSRRequestIssued(req.ID, rec.ID, cfg.DecisionNote); err != nil {
		return storage.PublicCert{}, err
	}
	logAuditEvent(store, "approve_csr_public", "csr_request", req.ID, req.CommonName)
	return rec, nil
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
	csr, err := parseCSRRequest(req)
	if err != nil {
		return storage.PrivateCert{}, err
	}

	issuerPassword, err := util.ResolveCryptoPassword(cfg.ParentPassword, cfg.StoragePassword)
	if err != nil {
		return storage.PrivateCert{}, fmt.Errorf("intermediate CA password required: %w", err)
	}

	var icaRec storage.PrivateIntermediateCA
	switch {
	case strings.TrimSpace(cfg.IntermediateID) != "":
		icaRec, err = store.GetPrivateIntermediateCAByID(cfg.IntermediateID)
	case strings.TrimSpace(cfg.IntermediateName) != "":
		icaRec, err = store.GetIssuingPrivateIntermediateCAByName(cfg.IntermediateName)
	case strings.TrimSpace(req.RequestedCAName) != "":
		icaRec, err = store.GetIssuingPrivateIntermediateCAByName(req.RequestedCAName)
	case strings.TrimSpace(rootCfg.DefaultIntermediateName) != "":
		icaRec, err = store.GetIssuingPrivateIntermediateCAByName(rootCfg.DefaultIntermediateName)
	default:
		err = fmt.Errorf("one of --intermediate-id, --intermediate-name, request requested-ca-name, or --default-intermediate-ca is required")
	}
	if err != nil {
		return storage.PrivateCert{}, err
	}
	if icaRec.Status != storage.StatusActive || !icaRec.IsIssuing {
		return storage.PrivateCert{}, fmt.Errorf("intermediate CA %q is not active for issuance", icaRec.ID)
	}

	if err := warnPrivateSANConflicts(store, req.CommonName, append([]string{req.CommonName}, splitSANCSV(req.SANsCSV)...)); err != nil {
		return storage.PrivateCert{}, err
	}

	icaKeyPEM, err := cli.Decrypt(icaRec.KeyPEM, issuerPassword)
	if err != nil {
		return storage.PrivateCert{}, fmt.Errorf("failed to decrypt intermediate CA private key: %w", err)
	}
	icaCert, err := privateca.ParseCertPEM(icaRec.CertPEM)
	if err != nil {
		return storage.PrivateCert{}, fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
	}
	icaKey, err := privateca.ParsePrivateKeyPEM(icaKeyPEM)
	if err != nil {
		return storage.PrivateCert{}, fmt.Errorf("failed to parse intermediate CA private key: %w", err)
	}

	effectiveCertType := firstNonEmpty(strings.TrimSpace(cfg.CertType), strings.TrimSpace(req.CertType), "server")
	effectiveDays := cfg.Days
	if effectiveDays <= 0 {
		effectiveDays = req.RequestedDays
	}
	if effectiveDays <= 0 {
		effectiveDays = 825
	}

	res, err := privateca.IssueLeafFromCSR(icaCert, icaKey, csr, privateca.IssueLeafFromCSROptions{
		CertType: effectiveCertType,
		Days:     effectiveDays,
	})
	if err != nil {
		return storage.PrivateCert{}, err
	}

	rec := storage.PrivateCert{
		ID:               util.NewID(),
		IntermediateCAID: icaRec.ID,
		CommonName:       req.CommonName,
		SANsCSV:          req.SANsCSV,
		CertType:         effectiveCertType,
		KeyType:          privateca.PublicKeyType(csr.PublicKey),
		CertPEM:          res.CertPEM,
		KeyPEM:           nil,
		Issuer:           res.Issuer,
		NotBefore:        res.NotBefore,
		NotAfter:         res.NotAfter,
	}
	if err := store.UpsertPrivateCert(rec); err != nil {
		return storage.PrivateCert{}, err
	}
	rec, err = store.GetPrivateCertByID(rec.ID)
	if err != nil {
		return storage.PrivateCert{}, err
	}
	if err := store.MarkCSRRequestIssued(req.ID, rec.ID, cfg.DecisionNote); err != nil {
		return storage.PrivateCert{}, err
	}
	logAuditEvent(store, "approve_csr_private", "csr_request", req.ID, req.CommonName)
	return rec, nil
}

func publicCSRNames(csr *x509.CertificateRequest) []string {
	names := make([]string, 0, len(csr.DNSNames)+1)
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" {
		names = append(names, cn)
	}
	names = append(names, csr.DNSNames...)
	return uniqueSorted(names)
}

func validatePublicCSR(csr *x509.CertificateRequest) error {
	if len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 || len(csr.IPAddresses) > 0 {
		return fmt.Errorf("public CSR requests only support DNS names")
	}
	names := publicCSRNames(csr)
	if len(names) == 0 {
		return fmt.Errorf("public CSR request must include at least one DNS name")
	}
	for _, name := range names {
		if net.ParseIP(name) != nil {
			return fmt.Errorf("public CSR requests only support DNS names")
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
