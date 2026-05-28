package cmd

import (
	"bytes"
	"crypto/x509"
	"strings"

	"certctl/internal/privateca"
	"certctl/internal/storage"
)

func privateKeyStored(keyPEM []byte) bool {
	return len(bytes.TrimSpace(keyPEM)) > 0
}

func parseCSRRequest(req storage.CSRRequest) (*x509.CertificateRequest, error) {
	csr, _, err := privateca.ParseCertificateRequest(req.CSRPEM)
	return csr, err
}

func csrRequestPayload(req storage.CSRRequest, includeCSR bool) map[string]any {
	payload := map[string]any{
		"id":                 req.ID,
		"kind":               req.Kind,
		"status":             req.Status,
		"common_name":        req.CommonName,
		"sans_csv":           req.SANsCSV,
		"requester_name":     req.RequesterName,
		"requester_email":    req.RequesterEmail,
		"phone_number":       req.PhoneNumber,
		"organization":       req.Organization,
		"department":         req.Department,
		"note":               req.Note,
		"requested_ca_name":  req.RequestedCAName,
		"cert_type":          req.CertType,
		"requested_days":     intToNil(req.RequestedDays),
		"issued_cert_id":     emptyStringToNil(req.IssuedCertID),
		"decision_note":      emptyStringToNil(req.DecisionNote),
		"fingerprint_sha256": req.FingerprintSHA256,
		"created_at":         formatTimeValue(req.CreatedAt),
		"updated_at":         formatTimeValue(req.UpdatedAt),
		"reviewed_at":        formatTimeValue(req.ReviewedAt),
	}
	if includeCSR {
		payload["csr_pem"] = string(req.CSRPEM)
	}
	return payload
}

func emptyStringToNil(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func intToNil(v int) any {
	if v <= 0 {
		return nil
	}
	return v
}

func splitSANCSV(csv string) []string {
	var out []string
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
