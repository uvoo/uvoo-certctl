package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"certctl/internal/csrqueue"
	"certctl/internal/storage"
	"certctl/internal/util"
)

type csrSubmitJSON struct {
	Kind            string `json:"kind"`
	CSRPEM          string `json:"csr_pem"`
	SubmitPassword  string `json:"submit_password"`
	RequesterName   string `json:"requester_name"`
	RequesterEmail  string `json:"requester_email"`
	PhoneNumber     string `json:"phone_number"`
	Organization    string `json:"organization"`
	Department      string `json:"department"`
	Note            string `json:"note"`
	RequestedCAName string `json:"requested_ca_name"`
	CertType        string `json:"cert_type"`
	RequestedDays   int    `json:"requested_days"`
}

func (s *Server) handleCSRRequests(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/csr-requests" && r.Method == http.MethodPost:
		s.handleCSRSubmit(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/csr-requests/") && r.Method == http.MethodGet:
		s.handleCSRStatus(w, r)
		return
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
}

func (s *Server) handleCSRSubmit(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.CSRSubmitPassword) == "" {
		writeError(w, http.StatusForbidden, "csr submission is not enabled")
		return
	}

	submission, submitPassword, err := parseCSRSubmission(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if submitPassword != s.cfg.CSRSubmitPassword {
		writeError(w, http.StatusForbidden, "invalid submission password")
		return
	}

	prepared, err := csrqueue.Prepare(submission)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	if err := store.CreateCSRRequest(prepared.Request); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store csr request")
		return
	}
	_ = store.LogAuditEvent(storage.AuditEvent{
		ID:         util.NewID(),
		Action:     "submit_csr_http",
		TargetKind: "csr_request",
		TargetID:   prepared.Request.ID,
		Summary:    prepared.Request.CommonName,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":           prepared.Request.ID,
		"kind":         prepared.Request.Kind,
		"status":       prepared.Request.Status,
		"common_name":  prepared.Request.CommonName,
		"sans_csv":     prepared.Request.SANsCSV,
		"pickup_token": prepared.PickupToken,
	})
}

func (s *Server) handleCSRStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/csr-requests/")
	id = strings.Trim(id, "/")
	if id == "" {
		writeError(w, http.StatusNotFound, "csr request not found")
		return
	}

	pickupToken := strings.TrimSpace(r.URL.Query().Get("pickup_token"))
	if pickupToken == "" {
		pickupToken = strings.TrimSpace(r.Header.Get("X-Pickup-Token"))
	}
	if pickupToken == "" {
		writeError(w, http.StatusForbidden, "pickup token required")
		return
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	req, err := store.GetCSRRequestByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "csr request not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load csr request")
		return
	}
	if err := util.CheckPassword(req.PickupTokenHash, pickupToken); err != nil {
		writeError(w, http.StatusForbidden, "invalid pickup token")
		return
	}

	resp := map[string]any{
		"id":             req.ID,
		"kind":           req.Kind,
		"status":         req.Status,
		"common_name":    req.CommonName,
		"sans_csv":       req.SANsCSV,
		"issued_cert_id": nilIfEmpty(req.IssuedCertID),
		"decision_note":  nilIfEmpty(req.DecisionNote),
		"created_at":     formatTime(req.CreatedAt),
		"updated_at":     formatTime(req.UpdatedAt),
		"reviewed_at":    formatTime(req.ReviewedAt),
		"requester_name": nilIfEmpty(req.RequesterName),
		"organization":   nilIfEmpty(req.Organization),
		"department":     nilIfEmpty(req.Department),
	}

	if req.Status == storage.CSRStatusIssued && req.IssuedCertID != "" {
		switch req.Kind {
		case storage.CertKindPublic:
			cert, err := store.GetPublicCertByID(req.IssuedCertID)
			if err == nil {
				resp["certificate_pem"] = string(cert.CertPEM)
			}
		case storage.CertKindPrivate:
			cert, err := store.GetPrivateCertByID(req.IssuedCertID)
			if err == nil {
				resp["certificate_pem"] = string(cert.CertPEM)
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func parseCSRSubmission(r *http.Request) (csrqueue.Submission, string, error) {
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.HasPrefix(contentType, "multipart/form-data") || strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		if err := r.ParseMultipartForm(8 << 20); err != nil && err != http.ErrNotMultipart {
			return csrqueue.Submission{}, "", err
		}
		if err := r.ParseForm(); err != nil {
			return csrqueue.Submission{}, "", err
		}

		csrData, err := readCSRFromForm(r)
		if err != nil {
			return csrqueue.Submission{}, "", err
		}

		return csrqueue.Submission{
			Kind:            r.FormValue("kind"),
			CSRData:         csrData,
			RequesterName:   r.FormValue("requester_name"),
			RequesterEmail:  r.FormValue("requester_email"),
			PhoneNumber:     r.FormValue("phone_number"),
			Organization:    r.FormValue("organization"),
			Department:      r.FormValue("department"),
			Note:            r.FormValue("note"),
			RequestedCAName: r.FormValue("requested_ca_name"),
			CertType:        r.FormValue("cert_type"),
			RequestedDays:   parseInt(r.FormValue("requested_days")),
		}, r.FormValue("submit_password"), nil
	}

	var req csrSubmitJSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return csrqueue.Submission{}, "", err
	}
	return csrqueue.Submission{
		Kind:            req.Kind,
		CSRData:         []byte(req.CSRPEM),
		RequesterName:   req.RequesterName,
		RequesterEmail:  req.RequesterEmail,
		PhoneNumber:     req.PhoneNumber,
		Organization:    req.Organization,
		Department:      req.Department,
		Note:            req.Note,
		RequestedCAName: req.RequestedCAName,
		CertType:        req.CertType,
		RequestedDays:   req.RequestedDays,
	}, req.SubmitPassword, nil
}

func readCSRFromForm(r *http.Request) ([]byte, error) {
	file, _, err := r.FormFile("csr")
	if err == nil {
		defer file.Close()
		return io.ReadAll(file)
	}
	if v := strings.TrimSpace(r.FormValue("csr_pem")); v != "" {
		return []byte(v), nil
	}
	return nil, err
}

func parseInt(v string) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var out int
	_, _ = fmt.Sscanf(v, "%d", &out)
	return out
}

func nilIfEmpty(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}
