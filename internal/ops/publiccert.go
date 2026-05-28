package ops

import (
	"fmt"
	"time"

	"certctl/internal/acme"
	"certctl/internal/cli"
	"certctl/internal/dns"
	"certctl/internal/storage"
	"certctl/internal/util"
)

type IssuePublicCertParams struct {
	Provider            ProviderConfig
	CommonName          string
	SANs                []string
	Email               string
	KeyType             string
	Timeout             time.Duration
	Propagation         time.Duration
	SkipChecks          bool
	Staging             bool
	Force               bool
	SkipIfExpiresWithin time.Duration
	CryptoPassword      string
}

type IssuePublicCertResult struct {
	Record   storage.PublicCert
	Warnings []SANConflict
	SANs     []string
	Skipped  bool
}

func IssuePublicCert(store *storage.Store, params IssuePublicCertParams) (IssuePublicCertResult, error) {
	ctx, cancel := WithTimeout(params.Timeout)
	defer cancel()

	provider, err := NewProvider(ctx, params.Provider)
	if err != nil {
		return IssuePublicCertResult{}, err
	}

	_, sansCSV, sansHash := storage.NormalizeSANs(params.SANs)

	if !params.SkipChecks {
		if err := dns.CheckPrecursors(ctx, provider, params.CommonName, params.Provider.DNSResolver, false); err != nil {
			return IssuePublicCertResult{}, err
		}
	}

	warnings, err := ListPublicSANConflicts(store, params.CommonName, params.SANs)
	if err != nil {
		return IssuePublicCertResult{}, err
	}

	if !params.Force {
		if existing, err := store.FindByHash(params.CommonName, sansHash); err == nil {
			remaining := time.Until(existing.NotAfter)
			if remaining > params.SkipIfExpiresWithin {
				return IssuePublicCertResult{
					Record:   existing,
					Warnings: warnings,
					SANs:     params.SANs,
					Skipped:  true,
				}, nil
			}
		}
	}

	if _, err := store.FindByHash(params.CommonName, sansHash); err == nil {
		return IssuePublicCertResult{
			Warnings: warnings,
			SANs:     params.SANs,
			Skipped:  true,
		}, nil
	}

	certs, err := acme.Issue(ctx, acme.IssueOptions{
		Email:       params.Email,
		Domains:     params.SANs,
		Provider:    params.Provider.Provider,
		APIUser:     params.Provider.APIUser,
		APIKey:      params.Provider.APIKey,
		ClientIP:    params.Provider.ClientIP,
		Timeout:     params.Timeout,
		UseStaging:  params.Staging,
		Propagation: params.Propagation,
		KeyType:     params.KeyType,
	})
	if err != nil {
		return IssuePublicCertResult{}, err
	}

	encKey, err := cli.Encrypt(certs.PrivateKey, params.CryptoPassword)
	if err != nil {
		return IssuePublicCertResult{}, err
	}

	issuer, notBefore, notAfter, err := storage.ParseCertMetadata(certs.Certificate)
	if err != nil {
		return IssuePublicCertResult{}, err
	}

	rec := storage.PublicCert{
		ID:         util.NewID(),
		CommonName: params.CommonName,
		SANsCSV:    sansCSV,
		SANsHash:   sansHash,
		CertPEM:    certs.Certificate,
		KeyPEM:     encKey,
		Provider:   params.Provider.Provider,
		Email:      params.Email,
		Issuer:     issuer,
		NotBefore:  notBefore,
		NotAfter:   notAfter,
	}
	if err := store.Upsert(rec); err != nil {
		return IssuePublicCertResult{}, err
	}
	rec, err = store.GetByCommonName(params.CommonName)
	if err != nil {
		return IssuePublicCertResult{}, err
	}
	LogAuditEvent(store, "issue_public_cert", "public_cert", rec.ID, rec.CommonName)
	return IssuePublicCertResult{Record: rec, Warnings: warnings, SANs: params.SANs}, nil
}

func ValidatePublicIssuePasswords(keyPassword, storagePassword string) error {
	if keyPassword != "" {
		if err := util.IsPasswordComplex(keyPassword); err != nil {
			return fmt.Errorf("invalid key-password: %w", err)
		}
	}
	if storagePassword != "" {
		if err := util.IsPasswordComplex(storagePassword); err != nil {
			return fmt.Errorf("invalid storage-password: %w", err)
		}
	}
	return nil
}
