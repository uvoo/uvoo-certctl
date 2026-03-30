package server

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"certctl/internal/ops"
	"certctl/internal/storage"
)

const (
	defaultAdminCSRTimeout            = 10 * time.Minute
	defaultAdminCSRPropagationTimeout = 30 * time.Minute
)

type adminApproveCSRRequest struct {
	Email                     string `json:"email"`
	Provider                  string `json:"provider"`
	APIUser                   string `json:"api_user"`
	APIKey                    string `json:"api_key"`
	ClientIP                  string `json:"client_ip"`
	DNSResolver               string `json:"dns_resolver"`
	Staging                   bool   `json:"staging"`
	TimeoutSeconds            int    `json:"timeout_seconds"`
	PropagationTimeoutSeconds int    `json:"propagation_timeout_seconds"`
	SkipChecks                bool   `json:"skip_checks"`
	DecisionNote              string `json:"decision_note"`

	IntermediateID    string `json:"intermediate_id"`
	IntermediateName  string `json:"intermediate_name"`
	ParentKeyPassword string `json:"parent_key_password"`
	StoragePassword   string `json:"storage_password"`
	CertType          string `json:"cert_type"`
	Days              int    `json:"days"`
}

type adminRejectCSRRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) adminAPIEnabled() bool {
	return strings.TrimSpace(s.cfg.AdminUsername) != "" && s.cfg.AdminPassword != ""
}

func (s *Server) requireAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !secureCompare(user, s.cfg.AdminUsername) || !secureCompare(pass, s.cfg.AdminPassword) {
			w.Header().Set("WWW-Authenticate", `Basic realm="certctl"`)
			writeError(w, http.StatusUnauthorized, "admin authentication required")
			return
		}
		next(w, r)
	}
}

func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) handleAdminDoctor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	warnDays := s.cfg.AdminWarnDays
	if raw := strings.TrimSpace(r.URL.Query().Get("warn_days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "warn_days must be an integer")
			return
		}
		warnDays = parsed
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	findings, err := ops.RunDoctor(store, warnDays)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to run doctor")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    ops.DoctorStatus(findings),
		"warn_days": warnDays,
		"findings":  findings,
	})
}

func (s *Server) handleAdminCSRRequests(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/admin/v1/csr-requests" && r.Method == http.MethodGet:
		s.handleAdminCSRList(w, r)
		return
	case r.URL.Path == "/admin/v1/csr-requests" && r.Method == http.MethodPost:
		s.handleAdminCSRSubmit(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/admin/v1/csr-requests/") && r.Method == http.MethodGet:
		s.handleAdminCSRGet(w, r)
		return
	case strings.HasSuffix(r.URL.Path, "/approve") && r.Method == http.MethodPost:
		s.handleAdminCSRApprove(w, r)
		return
	case strings.HasSuffix(r.URL.Path, "/reject") && r.Method == http.MethodPost:
		s.handleAdminCSRReject(w, r)
		return
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
}

func (s *Server) handleAdminCSRList(w http.ResponseWriter, r *http.Request) {
	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	all := parseBoolQuery(r, "all")
	if !all && status == "" {
		status = storage.CSRStatusPending
	}

	rows, err := store.ListCSRRequests(kind, status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list csr requests")
		return
	}

	includeCSR := parseBoolQuery(r, "include_csr")
	payload := make([]map[string]any, 0, len(rows))
	for _, req := range rows {
		payload = append(payload, csrRequestPayload(req, includeCSR))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": payload,
		"count": len(payload),
	})
}

func (s *Server) handleAdminCSRGet(w http.ResponseWriter, r *http.Request) {
	id, action := adminCSRPathParts(r.URL.Path)
	if id == "" || action != "" {
		writeError(w, http.StatusNotFound, "csr request not found")
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

	writeJSON(w, http.StatusOK, csrRequestPayload(req, parseBoolQuery(r, "include_csr")))
}

func (s *Server) handleAdminCSRSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.CSRMaxBodyBytes)

	submission, _, err := parseCSRSubmission(r)
	if err != nil {
		if isBodyTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "csr submission body too large")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	result, err := ops.SubmitCSR(store, ops.SubmitCSRParams{
		Kind:            submission.Kind,
		CSRData:         submission.CSRData,
		RequesterName:   submission.RequesterName,
		RequesterEmail:  submission.RequesterEmail,
		PhoneNumber:     submission.PhoneNumber,
		Organization:    submission.Organization,
		Department:      submission.Department,
		Note:            submission.Note,
		RequestedCAName: submission.RequestedCAName,
		CertType:        submission.CertType,
		RequestedDays:   submission.RequestedDays,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := csrRequestPayload(result.Request, false)
	resp["pickup_token"] = result.PickupToken
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleAdminCSRApprove(w http.ResponseWriter, r *http.Request) {
	id, action := adminCSRPathParts(r.URL.Path)
	if id == "" || action != "approve" {
		writeError(w, http.StatusNotFound, "csr request not found")
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
	if req.Status != storage.CSRStatusPending {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("csr request %s is not pending", req.ID))
		return
	}

	var body adminApproveCSRRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	switch req.Kind {
	case storage.CertKindPublic:
		timeout := durationFromSeconds(body.TimeoutSeconds, defaultAdminCSRTimeout)
		propagation := durationFromSeconds(body.PropagationTimeoutSeconds, defaultAdminCSRPropagationTimeout)
		result, err := ops.ApprovePublicCSRRequest(store, ops.ApprovePublicCSRParams{
			Request: req,
			Provider: ops.ProviderConfig{
				Provider:    body.Provider,
				APIUser:     body.APIUser,
				APIKey:      body.APIKey,
				ClientIP:    body.ClientIP,
				DNSResolver: firstNonEmpty(body.DNSResolver, "8.8.8.8"),
				HTTPTimeout: s.cfg.ProviderHTTPTimeout,
			},
			Email:        firstNonEmpty(strings.TrimSpace(body.Email), req.RequesterEmail),
			Staging:      body.Staging,
			Timeout:      timeout,
			Propagation:  propagation,
			SkipChecks:   body.SkipChecks,
			DecisionNote: body.DecisionNote,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"request_id":         req.ID,
			"status":             storage.CSRStatusIssued,
			"kind":               req.Kind,
			"issued_cert_id":     result.Record.ID,
			"common_name":        result.Record.CommonName,
			"sans_csv":           result.Record.SANsCSV,
			"provider":           result.Record.Provider,
			"not_before":         formatTime(result.Record.NotBefore),
			"not_after":          formatTime(result.Record.NotAfter),
			"private_key_stored": privateKeyStored(result.Record.KeyPEM),
			"warnings":           sanConflictPayload(result.Warnings),
		})
		return

	case storage.CertKindPrivate:
		result, err := ops.ApprovePrivateCSRRequest(store, ops.ApprovePrivateCSRParams{
			Request:             req,
			IntermediateID:      body.IntermediateID,
			IntermediateName:    body.IntermediateName,
			DefaultIntermediate: s.cfg.DefaultIntermediateName,
			ParentPassword:      body.ParentKeyPassword,
			StoragePassword:     body.StoragePassword,
			CertType:            body.CertType,
			Days:                body.Days,
			DecisionNote:        body.DecisionNote,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"request_id":         req.ID,
			"status":             storage.CSRStatusIssued,
			"kind":               req.Kind,
			"issued_cert_id":     result.Record.ID,
			"common_name":        result.Record.CommonName,
			"sans_csv":           result.Record.SANsCSV,
			"cert_type":          result.Record.CertType,
			"intermediate_ca_id": result.Record.IntermediateCAID,
			"not_before":         formatTime(result.Record.NotBefore),
			"not_after":          formatTime(result.Record.NotAfter),
			"private_key_stored": privateKeyStored(result.Record.KeyPEM),
			"warnings":           sanConflictPayload(result.Warnings),
		})
		return
	default:
		writeError(w, http.StatusBadRequest, "unsupported csr kind")
		return
	}
}

func (s *Server) handleAdminCSRReject(w http.ResponseWriter, r *http.Request) {
	id, action := adminCSRPathParts(r.URL.Path)
	if id == "" || action != "reject" {
		writeError(w, http.StatusNotFound, "csr request not found")
		return
	}

	var body adminRejectCSRRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		writeError(w, http.StatusBadRequest, "reason is required")
		return
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	if err := ops.RejectCSRRequest(store, id, body.Reason); err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "csr request not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":            id,
		"status":        storage.CSRStatusRejected,
		"decision_note": body.Reason,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	payload, err := buildMetrics(store, s.cfg.AdminWarnDays)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build metrics")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(payload))
}

func buildMetrics(store *storage.Store, warnDays int) (string, error) {
	publicRows, err := store.List("", true)
	if err != nil {
		return "", err
	}
	privateRows, err := store.ListPrivateCerts("", true)
	if err != nil {
		return "", err
	}
	rootRows, err := store.ListPrivateRootCAs("", true)
	if err != nil {
		return "", err
	}
	icaRows, err := store.ListPrivateIntermediateCAs("", true)
	if err != nil {
		return "", err
	}
	shares, err := store.ListShares("")
	if err != nil {
		return "", err
	}
	csrRows, err := store.ListCSRRequests("", "")
	if err != nil {
		return "", err
	}

	var b strings.Builder
	now := time.Now().UTC()
	warnWindow := time.Duration(warnDays) * 24 * time.Hour

	publicByStatus := map[string]int{}
	for _, row := range publicRows {
		publicByStatus[row.Status]++
	}
	writeMetricHeader(&b, "certctl_certificates_total", "Total certificates by kind and status.")
	for status, count := range publicByStatus {
		writeMetricSample(&b, "certctl_certificates_total", map[string]string{"kind": "public", "status": status}, float64(count))
	}

	privateByStatus := map[string]int{}
	for _, row := range privateRows {
		privateByStatus[row.Status]++
	}
	for status, count := range privateByStatus {
		writeMetricSample(&b, "certctl_certificates_total", map[string]string{"kind": "private", "status": status}, float64(count))
	}

	writeMetricHeader(&b, "certctl_private_ca_total", "Total private CAs by type, status, trust, and issuing state.")
	rootByState := map[string]int{}
	for _, row := range rootRows {
		key := fmt.Sprintf("%s|%t|%t", row.Status, row.IsTrusted, row.IsIssuing)
		rootByState[key]++
	}
	for key, count := range rootByState {
		parts := strings.Split(key, "|")
		writeMetricSample(&b, "certctl_private_ca_total", map[string]string{
			"type":       "root",
			"status":     parts[0],
			"is_trusted": parts[1],
			"is_issuing": parts[2],
		}, float64(count))
	}
	icaByState := map[string]int{}
	for _, row := range icaRows {
		key := fmt.Sprintf("%s|%t|%t", row.Status, row.IsTrusted, row.IsIssuing)
		icaByState[key]++
	}
	for key, count := range icaByState {
		parts := strings.Split(key, "|")
		writeMetricSample(&b, "certctl_private_ca_total", map[string]string{
			"type":       "intermediate",
			"status":     parts[0],
			"is_trusted": parts[1],
			"is_issuing": parts[2],
		}, float64(count))
	}

	writeMetricHeader(&b, "certctl_csr_requests_total", "Total CSR requests by kind and status.")
	csrByState := map[string]int{}
	for _, row := range csrRows {
		key := row.Kind + "|" + row.Status
		csrByState[key]++
	}
	for key, count := range csrByState {
		parts := strings.SplitN(key, "|", 2)
		writeMetricSample(&b, "certctl_csr_requests_total", map[string]string{"kind": parts[0], "status": parts[1]}, float64(count))
	}

	writeMetricHeader(&b, "certctl_shares_total", "Total certificate shares by state.")
	shareCounts := map[string]int{}
	for _, sh := range shares {
		shareCounts[shareState(sh, now)]++
	}
	for state, count := range shareCounts {
		writeMetricSample(&b, "certctl_shares_total", map[string]string{"state": state}, float64(count))
	}

	if warnDays > 0 {
		writeMetricHeader(&b, "certctl_certificates_expiring_within_days_total", "Active certificates expiring within the configured warning window.")
		writeMetricSample(&b, "certctl_certificates_expiring_within_days_total", map[string]string{
			"kind": "public",
			"days": strconv.Itoa(warnDays),
		}, float64(countExpiringPublicCerts(publicRows, now, warnWindow)))
		writeMetricSample(&b, "certctl_certificates_expiring_within_days_total", map[string]string{
			"kind": "private",
			"days": strconv.Itoa(warnDays),
		}, float64(countExpiringPrivateCerts(privateRows, now, warnWindow)))

		writeMetricHeader(&b, "certctl_private_ca_expiring_within_days_total", "Active private CAs expiring within the configured warning window.")
		writeMetricSample(&b, "certctl_private_ca_expiring_within_days_total", map[string]string{
			"type": "root",
			"days": strconv.Itoa(warnDays),
		}, float64(countExpiringRootCAs(rootRows, now, warnWindow)))
		writeMetricSample(&b, "certctl_private_ca_expiring_within_days_total", map[string]string{
			"type": "intermediate",
			"days": strconv.Itoa(warnDays),
		}, float64(countExpiringIntermediateCAs(icaRows, now, warnWindow)))

		writeMetricHeader(&b, "certctl_pending_csr_requests_older_than_days_total", "Pending CSR requests older than the configured warning window.")
		writeMetricSample(&b, "certctl_pending_csr_requests_older_than_days_total", map[string]string{
			"days": strconv.Itoa(warnDays),
		}, float64(countStalePendingCSRs(csrRows, now, warnWindow)))
	}

	return b.String(), nil
}

func countExpiringPublicCerts(rows []storage.PublicCert, now time.Time, warnWindow time.Duration) int {
	count := 0
	for _, row := range rows {
		if row.Status == storage.StatusActive && !row.NotAfter.IsZero() {
			if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
				count++
			}
		}
	}
	return count
}

func countExpiringPrivateCerts(rows []storage.PrivateCert, now time.Time, warnWindow time.Duration) int {
	count := 0
	for _, row := range rows {
		if row.Status == storage.StatusActive && !row.NotAfter.IsZero() {
			if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
				count++
			}
		}
	}
	return count
}

func countExpiringRootCAs(rows []storage.PrivateRootCA, now time.Time, warnWindow time.Duration) int {
	count := 0
	for _, row := range rows {
		if row.Status == storage.StatusActive && !row.NotAfter.IsZero() {
			if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
				count++
			}
		}
	}
	return count
}

func countExpiringIntermediateCAs(rows []storage.PrivateIntermediateCA, now time.Time, warnWindow time.Duration) int {
	count := 0
	for _, row := range rows {
		if row.Status == storage.StatusActive && !row.NotAfter.IsZero() {
			if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
				count++
			}
		}
	}
	return count
}

func countStalePendingCSRs(rows []storage.CSRRequest, now time.Time, warnWindow time.Duration) int {
	count := 0
	for _, row := range rows {
		if row.Status == storage.CSRStatusPending && !row.CreatedAt.IsZero() && now.Sub(row.CreatedAt) >= warnWindow {
			count++
		}
	}
	return count
}

func shareState(sh storage.CertShare, now time.Time) string {
	switch {
	case !sh.RevokedAt.IsZero():
		return "revoked"
	case !sh.ExpiresAt.IsZero() && !sh.ExpiresAt.After(now):
		return "expired"
	default:
		return "active"
	}
}

func writeMetricHeader(b *strings.Builder, name, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s gauge\n", name)
}

func writeMetricSample(b *strings.Builder, name string, labels map[string]string, value float64) {
	b.WriteString(name)
	if len(labels) > 0 {
		first := true
		b.WriteByte('{')
		for key, value := range labels {
			if !first {
				b.WriteByte(',')
			}
			first = false
			fmt.Fprintf(b, `%s="%s"`, key, escapeMetricLabel(value))
		}
		b.WriteByte('}')
	}
	fmt.Fprintf(b, " %.0f\n", value)
}

func escapeMetricLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

func adminCSRPathParts(path string) (string, string) {
	trimmed := strings.TrimPrefix(path, "/admin/v1/csr-requests/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return "", ""
	}
	parts := strings.Split(trimmed, "/")
	id := parts[0]
	if len(parts) == 1 {
		return id, ""
	}
	return id, parts[1]
}

func csrRequestPayload(req storage.CSRRequest, includeCSR bool) map[string]any {
	payload := map[string]any{
		"id":                 req.ID,
		"kind":               req.Kind,
		"status":             req.Status,
		"common_name":        req.CommonName,
		"sans_csv":           req.SANsCSV,
		"requester_name":     emptyStringToNil(req.RequesterName),
		"requester_email":    emptyStringToNil(req.RequesterEmail),
		"phone_number":       emptyStringToNil(req.PhoneNumber),
		"organization":       emptyStringToNil(req.Organization),
		"department":         emptyStringToNil(req.Department),
		"note":               emptyStringToNil(req.Note),
		"requested_ca_name":  emptyStringToNil(req.RequestedCAName),
		"cert_type":          emptyStringToNil(req.CertType),
		"requested_days":     intToNil(req.RequestedDays),
		"issued_cert_id":     emptyStringToNil(req.IssuedCertID),
		"decision_note":      emptyStringToNil(req.DecisionNote),
		"fingerprint_sha256": req.FingerprintSHA256,
		"created_at":         formatTime(req.CreatedAt),
		"updated_at":         formatTime(req.UpdatedAt),
		"reviewed_at":        formatTime(req.ReviewedAt),
	}
	if includeCSR {
		payload["csr_pem"] = string(req.CSRPEM)
	}
	return payload
}

func sanConflictPayload(conflicts []ops.SANConflict) []map[string]any {
	if len(conflicts) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(conflicts))
	for _, conflict := range conflicts {
		out = append(out, map[string]any{
			"common_name": conflict.CommonName,
			"sans":        conflict.SANs,
		})
	}
	return out
}

func decodeJSONBody(r *http.Request, dest any) error {
	if err := json.NewDecoder(r.Body).Decode(dest); err != nil {
		return fmt.Errorf("invalid JSON body")
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

func parseBoolQuery(r *http.Request, key string) bool {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return false
	}
	out, err := strconv.ParseBool(v)
	return err == nil && out
}

func durationFromSeconds(v int, fallback time.Duration) time.Duration {
	if v <= 0 {
		return fallback
	}
	return time.Duration(v) * time.Second
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
