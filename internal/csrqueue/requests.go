package csrqueue

import (
	"fmt"
	"strings"

	"uvoocertctl/internal/privateca"
	"uvoocertctl/internal/storage"
	"uvoocertctl/internal/util"
)

type Submission struct {
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

type PreparedRequest struct {
	Request     storage.CSRRequest
	PickupToken string
}

func Prepare(sub Submission) (PreparedRequest, error) {
	sub.Kind = strings.ToLower(strings.TrimSpace(sub.Kind))
	if sub.Kind != storage.CertKindPublic && sub.Kind != storage.CertKindPrivate {
		return PreparedRequest{}, fmt.Errorf("kind must be %q or %q", storage.CertKindPublic, storage.CertKindPrivate)
	}

	csr, csrPEM, err := privateca.ParseCertificateRequest(sub.CSRData)
	if err != nil {
		return PreparedRequest{}, fmt.Errorf("failed to parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return PreparedRequest{}, fmt.Errorf("invalid csr signature: %w", err)
	}

	commonName, sans := privateca.CSRIdentity(csr)
	if strings.TrimSpace(commonName) == "" {
		return PreparedRequest{}, fmt.Errorf("csr must contain a common name or at least one subject alternative name")
	}

	pickupToken, err := util.NewShareToken()
	if err != nil {
		return PreparedRequest{}, err
	}
	pickupHash, err := util.HashPassword(pickupToken)
	if err != nil {
		return PreparedRequest{}, err
	}

	req := storage.CSRRequest{
		ID:                util.NewID(),
		Kind:              sub.Kind,
		Status:            storage.CSRStatusPending,
		CSRPEM:            csrPEM,
		FingerprintSHA256: privateca.CSRFingerprintSHA256(csrPEM),
		CommonName:        commonName,
		SANsCSV:           strings.Join(sans, ","),
		RequesterName:     strings.TrimSpace(sub.RequesterName),
		RequesterEmail:    strings.TrimSpace(sub.RequesterEmail),
		PhoneNumber:       strings.TrimSpace(sub.PhoneNumber),
		Organization:      strings.TrimSpace(sub.Organization),
		Department:        strings.TrimSpace(sub.Department),
		Note:              strings.TrimSpace(sub.Note),
		RequestedCAName:   strings.TrimSpace(sub.RequestedCAName),
		CertType:          strings.TrimSpace(sub.CertType),
		RequestedDays:     sub.RequestedDays,
		PickupTokenHash:   pickupHash,
	}

	return PreparedRequest{
		Request:     req,
		PickupToken: pickupToken,
	}, nil
}
