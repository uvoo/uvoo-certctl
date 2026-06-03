package ops

import (
	"fmt"
	"strings"

	"uvoo-certctl/internal/cli"
	"uvoo-certctl/internal/privateca"
	"uvoo-certctl/internal/storage"
	"uvoo-certctl/internal/util"
)

type CreatePrivateRootCAParams struct {
	Name           string
	CommonName     string
	Days           int
	KeyType        string
	CryptoPassword string
	Org            string
	OrgUnit        string
	Country        string
	Province       string
	Locality       string
}

func CreatePrivateRootCA(store *storage.Store, params CreatePrivateRootCAParams) (storage.PrivateRootCA, error) {
	res, _, _, err := privateca.CreateRootCA(privateca.CreateRootOptions{
		CommonName: params.CommonName,
		KeyType:    params.KeyType,
		Days:       params.Days,
		Org:        params.Org,
		OrgUnit:    params.OrgUnit,
		Country:    params.Country,
		Province:   params.Province,
		Locality:   params.Locality,
	})
	if err != nil {
		return storage.PrivateRootCA{}, err
	}

	encKey, err := cli.Encrypt(res.KeyPEM, params.CryptoPassword)
	if err != nil {
		return storage.PrivateRootCA{}, err
	}

	rec := storage.PrivateRootCA{
		ID:         util.NewID(),
		Name:       params.Name,
		CommonName: params.CommonName,
		Status:     storage.StatusActive,
		IsTrusted:  true,
		IsIssuing:  true,
		KeyType:    params.KeyType,
		CertPEM:    res.CertPEM,
		KeyPEM:     encKey,
		Issuer:     res.Issuer,
		NotBefore:  res.NotBefore,
		NotAfter:   res.NotAfter,
	}

	if err := store.UpsertPrivateRootCA(rec); err != nil {
		return storage.PrivateRootCA{}, err
	}
	rec, err = store.GetPrivateRootCAByID(rec.ID)
	if err != nil {
		return storage.PrivateRootCA{}, err
	}
	LogAuditEvent(store, "create_root_ca", "private_root_ca", rec.ID, rec.Name)
	return rec, nil
}

type CreatePrivateIntermediateCAParams struct {
	RootID              string
	RootName            string
	DefaultRootName     string
	Name                string
	CommonName          string
	Days                int
	KeyType             string
	IssuerPassword      string
	ChildCryptoPassword string
	Org                 string
	OrgUnit             string
	Country             string
	Province            string
	Locality            string
}

func CreatePrivateIntermediateCA(store *storage.Store, params CreatePrivateIntermediateCAParams) (storage.PrivateIntermediateCA, error) {
	var (
		rootRec storage.PrivateRootCA
		err     error
	)
	switch {
	case strings.TrimSpace(params.RootID) != "":
		rootRec, err = store.GetPrivateRootCAByID(params.RootID)
		if err != nil {
			return storage.PrivateIntermediateCA{}, fmt.Errorf("failed to load root CA %q: %w", params.RootID, err)
		}
	case strings.TrimSpace(params.RootName) != "":
		rootRec, err = store.GetIssuingPrivateRootCAByName(params.RootName)
		if err != nil {
			return storage.PrivateIntermediateCA{}, fmt.Errorf("failed to load issuing root CA %q: %w", params.RootName, err)
		}
	case strings.TrimSpace(params.DefaultRootName) != "":
		rootRec, err = store.GetIssuingPrivateRootCAByName(params.DefaultRootName)
		if err != nil {
			return storage.PrivateIntermediateCA{}, fmt.Errorf("failed to load issuing root CA %q: %w", params.DefaultRootName, err)
		}
	default:
		return storage.PrivateIntermediateCA{}, fmt.Errorf("one of root id, root name, or default root name is required")
	}
	if rootRec.Status != storage.StatusActive || !rootRec.IsIssuing {
		return storage.PrivateIntermediateCA{}, fmt.Errorf("root CA %q is not active for issuance", rootRec.ID)
	}

	rootKeyPEM, err := cli.Decrypt(rootRec.KeyPEM, params.IssuerPassword)
	if err != nil {
		return storage.PrivateIntermediateCA{}, fmt.Errorf("failed to decrypt root CA private key: %w", err)
	}
	rootCert, err := privateca.ParseCertPEM(rootRec.CertPEM)
	if err != nil {
		return storage.PrivateIntermediateCA{}, fmt.Errorf("failed to parse root CA certificate: %w", err)
	}
	rootKey, err := privateca.ParsePrivateKeyPEM(rootKeyPEM)
	if err != nil {
		return storage.PrivateIntermediateCA{}, fmt.Errorf("failed to parse root CA private key: %w", err)
	}

	res, _, _, err := privateca.CreateIntermediateCA(rootCert, rootKey, privateca.CreateIntermediateOptions{
		CommonName: params.CommonName,
		KeyType:    params.KeyType,
		Days:       params.Days,
		Org:        params.Org,
		OrgUnit:    params.OrgUnit,
		Country:    params.Country,
		Province:   params.Province,
		Locality:   params.Locality,
	})
	if err != nil {
		return storage.PrivateIntermediateCA{}, err
	}

	encKey, err := cli.Encrypt(res.KeyPEM, params.ChildCryptoPassword)
	if err != nil {
		return storage.PrivateIntermediateCA{}, err
	}

	rec := storage.PrivateIntermediateCA{
		ID:         util.NewID(),
		RootCAID:   rootRec.ID,
		Name:       params.Name,
		CommonName: params.CommonName,
		Status:     storage.StatusActive,
		IsTrusted:  true,
		IsIssuing:  true,
		KeyType:    params.KeyType,
		CertPEM:    res.CertPEM,
		KeyPEM:     encKey,
		Issuer:     res.Issuer,
		NotBefore:  res.NotBefore,
		NotAfter:   res.NotAfter,
	}

	if err := store.UpsertPrivateIntermediateCA(rec); err != nil {
		return storage.PrivateIntermediateCA{}, err
	}
	rec, err = store.GetPrivateIntermediateCAByID(rec.ID)
	if err != nil {
		return storage.PrivateIntermediateCA{}, err
	}
	LogAuditEvent(store, "create_intermediate_ca", "private_intermediate_ca", rec.ID, rec.Name)
	return rec, nil
}

type IssuePrivateCertParams struct {
	IntermediateID      string
	IntermediateName    string
	DefaultIntermediate string
	CommonName          string
	SANs                []string
	CertType            string
	Days                int
	KeyType             string
	IssuerPassword      string
	ChildCryptoPassword string
	Org                 string
	OrgUnit             string
	Country             string
	Province            string
	Locality            string
}

type IssuePrivateCertResult struct {
	Record   storage.PrivateCert
	Warnings []SANConflict
}

func IssuePrivateCert(store *storage.Store, params IssuePrivateCertParams) (IssuePrivateCertResult, error) {
	var (
		icaRec storage.PrivateIntermediateCA
		err    error
	)
	switch {
	case strings.TrimSpace(params.IntermediateID) != "":
		icaRec, err = store.GetPrivateIntermediateCAByID(params.IntermediateID)
		if err != nil {
			return IssuePrivateCertResult{}, fmt.Errorf("failed to load intermediate CA %q: %w", params.IntermediateID, err)
		}
	case strings.TrimSpace(params.IntermediateName) != "":
		icaRec, err = store.GetIssuingPrivateIntermediateCAByName(params.IntermediateName)
		if err != nil {
			return IssuePrivateCertResult{}, fmt.Errorf("failed to load issuing intermediate CA %q: %w", params.IntermediateName, err)
		}
	case strings.TrimSpace(params.DefaultIntermediate) != "":
		icaRec, err = store.GetIssuingPrivateIntermediateCAByName(params.DefaultIntermediate)
		if err != nil {
			return IssuePrivateCertResult{}, fmt.Errorf("failed to load issuing intermediate CA %q: %w", params.DefaultIntermediate, err)
		}
	default:
		return IssuePrivateCertResult{}, fmt.Errorf("one of intermediate id, intermediate name, or default intermediate is required")
	}
	if icaRec.Status != storage.StatusActive || !icaRec.IsIssuing {
		return IssuePrivateCertResult{}, fmt.Errorf("intermediate CA %q is not active for issuance", icaRec.ID)
	}

	warnings, err := ListPrivateSANConflicts(store, params.CommonName, params.SANs)
	if err != nil {
		return IssuePrivateCertResult{}, err
	}

	icaKeyPEM, err := cli.Decrypt(icaRec.KeyPEM, params.IssuerPassword)
	if err != nil {
		return IssuePrivateCertResult{}, fmt.Errorf("failed to decrypt intermediate CA private key: %w", err)
	}
	icaCert, err := privateca.ParseCertPEM(icaRec.CertPEM)
	if err != nil {
		return IssuePrivateCertResult{}, fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
	}
	icaKey, err := privateca.ParsePrivateKeyPEM(icaKeyPEM)
	if err != nil {
		return IssuePrivateCertResult{}, fmt.Errorf("failed to parse intermediate CA private key: %w", err)
	}

	res, _, err := privateca.IssueLeaf(icaCert, icaKey, privateca.IssueLeafOptions{
		CommonName: params.CommonName,
		SANs:       params.SANs,
		CertType:   params.CertType,
		KeyType:    params.KeyType,
		Days:       params.Days,
		Org:        params.Org,
		OrgUnit:    params.OrgUnit,
		Country:    params.Country,
		Province:   params.Province,
		Locality:   params.Locality,
	})
	if err != nil {
		return IssuePrivateCertResult{}, err
	}

	encKey, err := cli.Encrypt(res.KeyPEM, params.ChildCryptoPassword)
	if err != nil {
		return IssuePrivateCertResult{}, err
	}

	rec := storage.PrivateCert{
		ID:               util.NewID(),
		IntermediateCAID: icaRec.ID,
		CommonName:       params.CommonName,
		SANsCSV:          strings.Join(params.SANs, ","),
		CertType:         params.CertType,
		KeyType:          params.KeyType,
		CertPEM:          res.CertPEM,
		KeyPEM:           encKey,
		Issuer:           res.Issuer,
		Status:           storage.StatusActive,
		NotBefore:        res.NotBefore,
		NotAfter:         res.NotAfter,
	}

	if err := store.UpsertPrivateCert(rec); err != nil {
		return IssuePrivateCertResult{}, err
	}
	rec, err = store.GetPrivateCertByID(rec.ID)
	if err != nil {
		return IssuePrivateCertResult{}, err
	}
	LogAuditEvent(store, "issue_private_cert", "private_cert", rec.ID, rec.CommonName)
	return IssuePrivateCertResult{Record: rec, Warnings: warnings}, nil
}
