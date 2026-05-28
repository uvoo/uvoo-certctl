package ops

import (
	"fmt"
	"strings"
	"time"

	"uvoocertctl/internal/acme"
	"uvoocertctl/internal/cli"
	"uvoocertctl/internal/csrqueue"
	"uvoocertctl/internal/dns"
	"uvoocertctl/internal/privateca"
	"uvoocertctl/internal/storage"
	"uvoocertctl/internal/util"
)

type SubmitCSRParams struct {
	Kind            string
	CSRData         []byte
	RequesterName   string
	RequesterEmail  string
	PhoneNumber     string
	Organization    string
	Department      string
	Note            string
	RequestedCAName string
	CertType        string
	RequestedDays   int
}

type SubmitCSRResult struct {
	Request     storage.CSRRequest
	PickupToken string
}

func SubmitCSR(store *storage.Store, params SubmitCSRParams) (SubmitCSRResult, error) {
	prepared, err := csrqueue.Prepare(csrqueue.Submission{
		Kind:            params.Kind,
		CSRData:         params.CSRData,
		RequesterName:   params.RequesterName,
		RequesterEmail:  params.RequesterEmail,
		PhoneNumber:     params.PhoneNumber,
		Organization:    params.Organization,
		Department:      params.Department,
		Note:            params.Note,
		RequestedCAName: params.RequestedCAName,
		CertType:        params.CertType,
		RequestedDays:   params.RequestedDays,
	})
	if err != nil {
		return SubmitCSRResult{}, err
	}
	if err := store.CreateCSRRequest(prepared.Request); err != nil {
		return SubmitCSRResult{}, err
	}
	LogAuditEvent(store, "submit_csr", "csr_request", prepared.Request.ID, prepared.Request.CommonName)
	return SubmitCSRResult{Request: prepared.Request, PickupToken: prepared.PickupToken}, nil
}

func RejectCSRRequest(store *storage.Store, id, reason string) error {
	if err := store.RejectCSRRequest(id, reason); err != nil {
		return err
	}
	LogAuditEvent(store, "reject_csr", "csr_request", id, reason)
	return nil
}

type ApprovePublicCSRParams struct {
	Request      storage.CSRRequest
	Provider     ProviderConfig
	Email        string
	Staging      bool
	Timeout      time.Duration
	Propagation  time.Duration
	SkipChecks   bool
	DecisionNote string
}

type ApprovePublicCSRResult struct {
	Record   storage.PublicCert
	Warnings []SANConflict
}

func ApprovePublicCSRRequest(store *storage.Store, params ApprovePublicCSRParams) (ApprovePublicCSRResult, error) {
	csr, err := ParseCSRRequest(params.Request)
	if err != nil {
		return ApprovePublicCSRResult{}, err
	}
	if err := ValidatePublicCSR(csr); err != nil {
		return ApprovePublicCSRResult{}, err
	}

	ctx, cancel := WithTimeout(params.Timeout)
	defer cancel()

	provider, err := NewProvider(ctx, params.Provider)
	if err != nil {
		return ApprovePublicCSRResult{}, err
	}

	names := PublicCSRNames(csr)
	if !params.SkipChecks {
		for _, name := range names {
			if err := dns.CheckPrecursors(ctx, provider, name, params.Provider.DNSResolver, false); err != nil {
				return ApprovePublicCSRResult{}, err
			}
		}
	}

	warnings, err := ListPublicSANConflicts(store, params.Request.CommonName, append([]string{params.Request.CommonName}, names...))
	if err != nil {
		return ApprovePublicCSRResult{}, err
	}

	resource, err := acme.IssueForCSR(ctx, acme.IssueForCSROptions{
		Email:       params.Email,
		CSR:         csr,
		Provider:    params.Provider.Provider,
		APIUser:     params.Provider.APIUser,
		APIKey:      params.Provider.APIKey,
		ClientIP:    params.Provider.ClientIP,
		DNSResolver: params.Provider.DNSResolver,
		Timeout:     params.Timeout,
		UseStaging:  params.Staging,
		Propagation: params.Propagation,
	})
	if err != nil {
		return ApprovePublicCSRResult{}, err
	}

	_, sansCSV, sansHash := storage.NormalizeSANs(PublicCSRNames(csr))
	issuer, notBefore, notAfter, err := storage.ParseCertMetadata(resource.Certificate)
	if err != nil {
		return ApprovePublicCSRResult{}, err
	}

	rec := storage.PublicCert{
		ID:         util.NewID(),
		CommonName: params.Request.CommonName,
		SANsCSV:    sansCSV,
		SANsHash:   sansHash,
		CertPEM:    resource.Certificate,
		KeyPEM:     nil,
		Provider:   params.Provider.Provider,
		Email:      params.Email,
		Issuer:     issuer,
		NotBefore:  notBefore,
		NotAfter:   notAfter,
	}
	if err := store.Upsert(rec); err != nil {
		return ApprovePublicCSRResult{}, err
	}
	rec, err = store.GetByCommonName(params.Request.CommonName)
	if err != nil {
		return ApprovePublicCSRResult{}, err
	}
	if err := store.MarkCSRRequestIssued(params.Request.ID, rec.ID, params.DecisionNote); err != nil {
		return ApprovePublicCSRResult{}, err
	}
	LogAuditEvent(store, "approve_csr_public", "csr_request", params.Request.ID, params.Request.CommonName)
	return ApprovePublicCSRResult{Record: rec, Warnings: warnings}, nil
}

type ApprovePrivateCSRParams struct {
	Request             storage.CSRRequest
	IntermediateID      string
	IntermediateName    string
	DefaultIntermediate string
	ParentPassword      string
	StoragePassword     string
	CertType            string
	Days                int
	DecisionNote        string
}

type ApprovePrivateCSRResult struct {
	Record   storage.PrivateCert
	Warnings []SANConflict
}

func ApprovePrivateCSRRequest(store *storage.Store, params ApprovePrivateCSRParams) (ApprovePrivateCSRResult, error) {
	csr, err := ParseCSRRequest(params.Request)
	if err != nil {
		return ApprovePrivateCSRResult{}, err
	}

	issuerPassword, err := util.ResolveCryptoPassword(params.ParentPassword, params.StoragePassword)
	if err != nil {
		return ApprovePrivateCSRResult{}, fmt.Errorf("intermediate CA password required: %w", err)
	}

	var icaRec storage.PrivateIntermediateCA
	switch {
	case strings.TrimSpace(params.IntermediateID) != "":
		icaRec, err = store.GetPrivateIntermediateCAByID(params.IntermediateID)
	case strings.TrimSpace(params.IntermediateName) != "":
		icaRec, err = store.GetIssuingPrivateIntermediateCAByName(params.IntermediateName)
	case strings.TrimSpace(params.Request.RequestedCAName) != "":
		icaRec, err = store.GetIssuingPrivateIntermediateCAByName(params.Request.RequestedCAName)
	case strings.TrimSpace(params.DefaultIntermediate) != "":
		icaRec, err = store.GetIssuingPrivateIntermediateCAByName(params.DefaultIntermediate)
	default:
		err = fmt.Errorf("one of intermediate id, intermediate name, requested-ca-name, or default intermediate is required")
	}
	if err != nil {
		return ApprovePrivateCSRResult{}, err
	}
	if icaRec.Status != storage.StatusActive || !icaRec.IsIssuing {
		return ApprovePrivateCSRResult{}, fmt.Errorf("intermediate CA %q is not active for issuance", icaRec.ID)
	}

	warnings, err := ListPrivateSANConflicts(store, params.Request.CommonName, append([]string{params.Request.CommonName}, SplitSANCSV(params.Request.SANsCSV)...))
	if err != nil {
		return ApprovePrivateCSRResult{}, err
	}

	icaKeyPEM, err := cli.Decrypt(icaRec.KeyPEM, issuerPassword)
	if err != nil {
		return ApprovePrivateCSRResult{}, fmt.Errorf("failed to decrypt intermediate CA private key: %w", err)
	}
	icaCert, err := privateca.ParseCertPEM(icaRec.CertPEM)
	if err != nil {
		return ApprovePrivateCSRResult{}, fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
	}
	icaKey, err := privateca.ParsePrivateKeyPEM(icaKeyPEM)
	if err != nil {
		return ApprovePrivateCSRResult{}, fmt.Errorf("failed to parse intermediate CA private key: %w", err)
	}

	effectiveCertType := FirstNonEmpty(params.CertType, params.Request.CertType, "server")
	effectiveDays := params.Days
	if effectiveDays <= 0 {
		effectiveDays = params.Request.RequestedDays
	}
	if effectiveDays <= 0 {
		effectiveDays = 825
	}

	res, err := privateca.IssueLeafFromCSR(icaCert, icaKey, csr, privateca.IssueLeafFromCSROptions{
		CertType: effectiveCertType,
		Days:     effectiveDays,
	})
	if err != nil {
		return ApprovePrivateCSRResult{}, err
	}

	rec := storage.PrivateCert{
		ID:               util.NewID(),
		IntermediateCAID: icaRec.ID,
		CommonName:       params.Request.CommonName,
		SANsCSV:          params.Request.SANsCSV,
		CertType:         effectiveCertType,
		KeyType:          privateca.PublicKeyType(csr.PublicKey),
		CertPEM:          res.CertPEM,
		KeyPEM:           nil,
		Issuer:           res.Issuer,
		NotBefore:        res.NotBefore,
		NotAfter:         res.NotAfter,
	}
	if err := store.UpsertPrivateCert(rec); err != nil {
		return ApprovePrivateCSRResult{}, err
	}
	rec, err = store.GetPrivateCertByID(rec.ID)
	if err != nil {
		return ApprovePrivateCSRResult{}, err
	}
	if err := store.MarkCSRRequestIssued(params.Request.ID, rec.ID, params.DecisionNote); err != nil {
		return ApprovePrivateCSRResult{}, err
	}
	LogAuditEvent(store, "approve_csr_private", "csr_request", params.Request.ID, params.Request.CommonName)
	return ApprovePrivateCSRResult{Record: rec, Warnings: warnings}, nil
}
