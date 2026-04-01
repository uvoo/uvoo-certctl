package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"certctl/internal/auth"
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

type adminApproveSubjectRequest struct {
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	LocalRoles  []string `json:"local_roles"`
	LocalGroups []string `json:"local_groups"`
}

type adminUpdateSubjectRequest struct {
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Status      string   `json:"status"`
	LocalRoles  []string `json:"local_roles"`
	LocalGroups []string `json:"local_groups"`
}

type adminUpsertSubjectAutoApprovalRuleRequest struct {
	Enabled        *bool    `json:"enabled"`
	Issuer         string   `json:"issuer"`
	EmailDomain    string   `json:"email_domain"`
	RequiredRoles  []string `json:"required_roles"`
	RequiredGroups []string `json:"required_groups"`
	LocalRoles     []string `json:"local_roles"`
	LocalGroups    []string `json:"local_groups"`
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

	findings, err := ops.RunDoctorWithOptions(store, ops.DoctorOptions{
		WarnDays: warnDays,
		AuthIssuerProbe: func(issuer storage.AuthIssuer) error {
			timeout := s.cfg.ProviderHTTPTimeout
			if timeout <= 0 {
				timeout = 10 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			return s.authVerifier.CheckIssuerConnectivity(ctx, issuer)
		},
	})
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

func (s *Server) handleAdminEffectiveAuthz(w http.ResponseWriter, r *http.Request) {
	identity, ok := authIdentityFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing authenticated identity")
		return
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	bindings, err := store.ListAuthzBindings(true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load authz bindings")
		return
	}

	var matchedIssuer any
	if !identity.Superuser && strings.TrimSpace(identity.Issuer) != "" {
		if issuers, err := store.ListAuthIssuers(true); err == nil {
			if issuer, ok := findAuthIssuerByIssuer(issuers, identity.Issuer); ok {
				matchedIssuer = authIssuerPayload(issuer)
			}
		}
	}

	var subjectRecord any
	if !identity.Superuser && strings.TrimSpace(identity.Issuer) != "" && strings.TrimSpace(identity.Subject) != "" {
		if rec, err := store.GetSubject(identity.Issuer, identity.Subject); err == nil {
			subjectRecord = subjectPayload(rec)
		}
	}

	effectivePermissions := auth.EffectivePermissions(identity, bindings)
	matchingBindings := collectMatchingBindings(identity, bindings, effectivePermissions)
	writeJSON(w, http.StatusOK, map[string]any{
		"matched_issuer":        matchedIssuer,
		"subject_record":        subjectRecord,
		"superuser":             identity.Superuser,
		"auth_method":           identity.AuthMethod,
		"issuer":                emptyStringToNil(identity.Issuer),
		"subject":               emptyStringToNil(identity.Subject),
		"username":              emptyStringToNil(identity.Username),
		"email":                 emptyStringToNil(identity.Email),
		"principals":            identity.Principals,
		"roles":                 identity.Roles,
		"groups":                identity.Groups,
		"local_roles":           identity.LocalRoles,
		"local_groups":          identity.LocalGroups,
		"effective_permissions": effectivePermissions,
		"matching_bindings":     matchingBindings,
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

func (s *Server) handleAdminSubjects(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/admin/v1/subjects" && r.Method == http.MethodGet:
		s.handleAdminSubjectList(w, r)
		return
	case r.URL.Path == "/admin/v1/subjects/approve" && r.Method == http.MethodPost:
		s.handleAdminSubjectApprove(w, r)
		return
	case r.URL.Path == "/admin/v1/subjects/update" && r.Method == http.MethodPost:
		s.handleAdminSubjectUpdate(w, r)
		return
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
}

func (s *Server) handleAdminSubjectAutoApprovals(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/admin/v1/subject-auto-approvals" && r.Method == http.MethodGet:
		s.handleAdminSubjectAutoApprovalList(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/admin/v1/subject-auto-approvals/") && r.Method == http.MethodGet:
		s.handleAdminSubjectAutoApprovalGet(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/admin/v1/subject-auto-approvals/") && r.Method == http.MethodPut:
		s.handleAdminSubjectAutoApprovalUpsert(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/admin/v1/subject-auto-approvals/") && r.Method == http.MethodDelete:
		s.handleAdminSubjectAutoApprovalDelete(w, r)
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

func (s *Server) handleAdminSubjectList(w http.ResponseWriter, r *http.Request) {
	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	rows, err := ops.ListSubjects(store, ops.SubjectFilter{
		ActiveOnly: !parseBoolQuery(r, "all"),
		Issuer:     strings.TrimSpace(r.URL.Query().Get("issuer")),
		Subject:    strings.TrimSpace(r.URL.Query().Get("subject")),
		Status:     strings.TrimSpace(r.URL.Query().Get("status")),
		LocalRole:  strings.TrimSpace(r.URL.Query().Get("local_role")),
		LocalGroup: strings.TrimSpace(r.URL.Query().Get("local_group")),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list subjects")
		return
	}

	payload := make([]map[string]any, 0, len(rows))
	for _, rec := range rows {
		payload = append(payload, subjectPayload(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": payload,
		"count": len(payload),
	})
}

func (s *Server) handleAdminSubjectApprove(w http.ResponseWriter, r *http.Request) {
	var body adminApproveSubjectRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	rec, err := ops.ApproveSubject(
		store,
		body.Issuer,
		body.Subject,
		body.LocalRoles,
		body.LocalGroups,
		body.LocalRoles != nil,
		body.LocalGroups != nil,
	)
	if err != nil {
		writeAdminStorageError(w, err, "subject")
		return
	}
	writeJSON(w, http.StatusOK, subjectPayload(rec))
}

func (s *Server) handleAdminSubjectUpdate(w http.ResponseWriter, r *http.Request) {
	var body adminUpdateSubjectRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.Status) == "" && body.LocalRoles == nil && body.LocalGroups == nil {
		writeError(w, http.StatusBadRequest, "at least one of status, local_roles, or local_groups is required")
		return
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	rec, err := ops.UpdateSubject(store, ops.UpdateSubjectParams{
		Issuer:       body.Issuer,
		Subject:      body.Subject,
		Status:       body.Status,
		LocalRoles:   body.LocalRoles,
		LocalGroups:  body.LocalGroups,
		ChangeStatus: strings.TrimSpace(body.Status) != "",
		ChangeRoles:  body.LocalRoles != nil,
		ChangeGroups: body.LocalGroups != nil,
	})
	if err != nil {
		writeAdminStorageError(w, err, "subject")
		return
	}
	writeJSON(w, http.StatusOK, subjectPayload(rec))
}

func (s *Server) handleAdminSubjectAutoApprovalList(w http.ResponseWriter, r *http.Request) {
	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	rows, err := ops.ListSubjectAutoApprovalRules(store, ops.SubjectAutoApprovalRuleFilter{
		EnabledOnly: !parseBoolQuery(r, "all"),
		Name:        strings.TrimSpace(r.URL.Query().Get("name")),
		Issuer:      strings.TrimSpace(r.URL.Query().Get("issuer")),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list subject auto approval rules")
		return
	}

	payload := make([]map[string]any, 0, len(rows))
	for _, rec := range rows {
		payload = append(payload, subjectAutoApprovalRulePayload(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": payload,
		"count": len(payload),
	})
}

func (s *Server) handleAdminSubjectAutoApprovalGet(w http.ResponseWriter, r *http.Request) {
	name := adminSubjectAutoApprovalRuleName(r.URL.Path)
	if name == "" {
		writeError(w, http.StatusNotFound, "subject auto approval rule not found")
		return
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	rec, err := store.GetSubjectAutoApprovalRuleByName(name)
	if err != nil {
		writeAdminStorageError(w, err, "subject auto approval rule")
		return
	}
	writeJSON(w, http.StatusOK, subjectAutoApprovalRulePayload(rec))
}

func (s *Server) handleAdminSubjectAutoApprovalUpsert(w http.ResponseWriter, r *http.Request) {
	name := adminSubjectAutoApprovalRuleName(r.URL.Path)
	if name == "" {
		writeError(w, http.StatusNotFound, "subject auto approval rule not found")
		return
	}

	var body adminUpsertSubjectAutoApprovalRuleRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	rec, err := ops.UpsertSubjectAutoApprovalRule(store, ops.UpsertSubjectAutoApprovalRuleParams{
		Name:           name,
		Enabled:        enabled,
		Issuer:         body.Issuer,
		EmailDomain:    body.EmailDomain,
		RequiredRoles:  body.RequiredRoles,
		RequiredGroups: body.RequiredGroups,
		LocalRoles:     body.LocalRoles,
		LocalGroups:    body.LocalGroups,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, subjectAutoApprovalRulePayload(rec))
}

func (s *Server) handleAdminSubjectAutoApprovalDelete(w http.ResponseWriter, r *http.Request) {
	name := adminSubjectAutoApprovalRuleName(r.URL.Path)
	if name == "" {
		writeError(w, http.StatusNotFound, "subject auto approval rule not found")
		return
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	rec, err := ops.DeleteSubjectAutoApprovalRule(store, name)
	if err != nil {
		writeAdminStorageError(w, err, "subject auto approval rule")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":    rec.Name,
		"issuer":  rec.Issuer,
		"deleted": true,
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

	payload, err := buildMetrics(store, s.cfg.AdminWarnDays, s.authResultSnapshot(), s.autoApprovalSnapshot())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build metrics")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(payload))
}

func buildMetrics(store *storage.Store, warnDays int, authResults map[string]int, autoApprovals map[string]int) (string, error) {
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
	authIssuers, err := store.ListAuthIssuers(false)
	if err != nil {
		return "", err
	}
	authzBindings, err := store.ListAuthzBindings(false)
	if err != nil {
		return "", err
	}
	subjectAutoApprovalRules, err := store.ListSubjectAutoApprovalRules(false)
	if err != nil {
		return "", err
	}
	subjects, err := store.ListSubjects(false)
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

	writeMetricHeader(&b, "certctl_pending_csr_requests_total", "Pending CSR requests by kind.")
	pendingCSRByKind := map[string]int{}
	readyCSRByKind := map[string]int{}
	for _, row := range csrRows {
		switch row.Status {
		case storage.CSRStatusPending:
			pendingCSRByKind[row.Kind]++
		case storage.CSRStatusIssued:
			readyCSRByKind[row.Kind]++
		}
	}
	for kind, count := range pendingCSRByKind {
		writeMetricSample(&b, "certctl_pending_csr_requests_total", map[string]string{"kind": kind}, float64(count))
	}

	writeMetricHeader(&b, "certctl_csr_requests_ready_for_pickup_total", "Issued CSR requests by kind that are ready for pickup.")
	for kind, count := range readyCSRByKind {
		writeMetricSample(&b, "certctl_csr_requests_ready_for_pickup_total", map[string]string{"kind": kind}, float64(count))
	}

	writeMetricHeader(&b, "certctl_auth_issuers_total", "Trusted auth issuers by enabled state.")
	authIssuerCounts := map[string]int{}
	for _, issuer := range authIssuers {
		authIssuerCounts[strconv.FormatBool(issuer.Enabled)]++
	}
	for enabled, count := range authIssuerCounts {
		writeMetricSample(&b, "certctl_auth_issuers_total", map[string]string{"enabled": enabled}, float64(count))
	}

	writeMetricHeader(&b, "certctl_authz_bindings_total", "Authorization bindings by enabled state and scope breadth.")
	authzBindingCounts := map[string]int{}
	for _, binding := range authzBindings {
		key := strconv.FormatBool(binding.Enabled) + "|" + authzBindingScope(binding)
		authzBindingCounts[key]++
	}
	for key, count := range authzBindingCounts {
		parts := strings.SplitN(key, "|", 2)
		writeMetricSample(&b, "certctl_authz_bindings_total", map[string]string{
			"enabled": parts[0],
			"scope":   parts[1],
		}, float64(count))
	}

	writeMetricHeader(&b, "certctl_subject_auto_approval_rules_total", "Subject auto-approval rules by enabled state.")
	subjectRuleCounts := map[string]int{}
	for _, rule := range subjectAutoApprovalRules {
		subjectRuleCounts[strconv.FormatBool(rule.Enabled)]++
	}
	for enabled, count := range subjectRuleCounts {
		writeMetricSample(&b, "certctl_subject_auto_approval_rules_total", map[string]string{"enabled": enabled}, float64(count))
	}

	writeMetricHeader(&b, "certctl_auth_requests_total", "Admin and metrics authentication attempts by result and auth method since process start.")
	for key, count := range authResults {
		parts := strings.SplitN(key, "|", 2)
		labels := map[string]string{"result": parts[0], "auth_method": "unknown"}
		if len(parts) == 2 && parts[1] != "" {
			labels["auth_method"] = parts[1]
		}
		writeMetricSample(&b, "certctl_auth_requests_total", labels, float64(count))
	}

	writeMetricHeader(&b, "certctl_subject_auto_approval_matches_total", "Subject auto-approval rule matches since process start.")
	for ruleName, count := range autoApprovals {
		writeMetricSample(&b, "certctl_subject_auto_approval_matches_total", map[string]string{"rule": ruleName}, float64(count))
	}

	writeMetricHeader(&b, "certctl_subjects_total", "Locally tracked JWT subjects by status.")
	subjectCounts := map[string]int{}
	pendingSubjects := 0
	for _, subject := range subjects {
		subjectCounts[subject.Status]++
		if subject.Status == storage.SubjectStatusPending {
			pendingSubjects++
		}
	}
	for status, count := range subjectCounts {
		writeMetricSample(&b, "certctl_subjects_total", map[string]string{"status": status}, float64(count))
	}
	writeMetricHeader(&b, "certctl_pending_subjects_total", "Locally tracked JWT subjects that are still pending approval.")
	writeMetricSample(&b, "certctl_pending_subjects_total", nil, float64(pendingSubjects))

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

		writeMetricHeader(&b, "certctl_pending_subjects_older_than_days_total", "Pending JWT subjects older than the configured warning window.")
		writeMetricSample(&b, "certctl_pending_subjects_older_than_days_total", map[string]string{
			"days": strconv.Itoa(warnDays),
		}, float64(countStalePendingSubjects(subjects, now, warnWindow)))
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

func authzBindingScope(binding storage.AuthzBinding) string {
	resourceKind := strings.TrimSpace(binding.ResourceKind)
	resourceRef := strings.TrimSpace(binding.ResourceRef)
	if resourceKind == "" || resourceKind == "*" || resourceRef == "" || resourceRef == "*" {
		return "wildcard"
	}
	return "scoped"
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

func countStalePendingSubjects(rows []storage.Subject, now time.Time, warnWindow time.Duration) int {
	count := 0
	for _, row := range rows {
		if row.Status != storage.SubjectStatusPending || row.FirstSeenAt.IsZero() {
			continue
		}
		if now.Sub(row.FirstSeenAt) >= warnWindow {
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

func authIdentityFromRequest(r *http.Request) (auth.Identity, bool) {
	return auth.IdentityFromContext(r.Context())
}

func writeAdminStorageError(w http.ResponseWriter, err error, noun string) {
	if err == nil {
		return
	}
	if err == sql.ErrNoRows || strings.Contains(strings.ToLower(err.Error()), "not found") {
		writeError(w, http.StatusNotFound, noun+" not found")
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func adminSubjectAutoApprovalRuleName(path string) string {
	name := strings.TrimSpace(strings.TrimPrefix(path, "/admin/v1/subject-auto-approvals/"))
	if name == "" || strings.Contains(name, "/") {
		return ""
	}
	return name
}

func subjectPayload(rec storage.Subject) map[string]any {
	return map[string]any{
		"id":            rec.ID,
		"issuer":        rec.Issuer,
		"subject":       rec.Subject,
		"status":        rec.Status,
		"username":      emptyStringToNil(rec.Username),
		"email":         emptyStringToNil(rec.Email),
		"roles":         rec.Roles,
		"groups":        rec.Groups,
		"local_roles":   rec.LocalRoles,
		"local_groups":  rec.LocalGroups,
		"auth_count":    rec.AuthCount,
		"first_seen_at": formatTimeValue(rec.FirstSeenAt),
		"last_seen_at":  formatTimeValue(rec.LastSeenAt),
		"updated_at":    formatTimeValue(rec.UpdatedAt),
	}
}

func subjectAutoApprovalRulePayload(rec storage.SubjectAutoApprovalRule) map[string]any {
	return map[string]any{
		"id":              rec.ID,
		"name":            rec.Name,
		"enabled":         rec.Enabled,
		"issuer":          rec.Issuer,
		"email_domain":    emptyStringToNil(rec.EmailDomain),
		"required_roles":  rec.RequiredRoles,
		"required_groups": rec.RequiredGroups,
		"local_roles":     rec.LocalRoles,
		"local_groups":    rec.LocalGroups,
		"created_at":      formatTimeValue(rec.CreatedAt),
		"updated_at":      formatTimeValue(rec.UpdatedAt),
	}
}

func collectMatchingBindings(identity auth.Identity, bindings []storage.AuthzBinding, permissions []string) []map[string]any {
	seen := map[string]struct{}{}
	var out []map[string]any
	for _, permission := range permissions {
		req := auth.PermissionRequest{Permission: permission}
		for _, binding := range auth.MatchingBindings(identity, bindings, req) {
			if _, ok := seen[binding.ID]; ok {
				continue
			}
			seen[binding.ID] = struct{}{}
			out = append(out, authzBindingPayload(binding))
		}
	}
	return out
}

func authzBindingPayload(binding storage.AuthzBinding) map[string]any {
	return map[string]any{
		"id":            binding.ID,
		"enabled":       binding.Enabled,
		"principal":     binding.Principal,
		"permission":    binding.Permission,
		"resource_kind": emptyStringToNil(binding.ResourceKind),
		"resource_ref":  emptyStringToNil(binding.ResourceRef),
		"created_at":    formatTimeValue(binding.CreatedAt),
		"updated_at":    formatTimeValue(binding.UpdatedAt),
	}
}

func findAuthIssuerByIssuer(rows []storage.AuthIssuer, issuer string) (storage.AuthIssuer, bool) {
	for _, row := range rows {
		if row.Issuer == issuer {
			return row, true
		}
	}
	return storage.AuthIssuer{}, false
}

func authIssuerPayload(rec storage.AuthIssuer) map[string]any {
	return map[string]any{
		"id":              rec.ID,
		"name":            rec.Name,
		"enabled":         rec.Enabled,
		"issuer":          rec.Issuer,
		"audiences":       rec.Audiences,
		"required_claims": rec.RequiredClaims,
		"discovery_url":   emptyStringToNil(rec.DiscoveryURL),
		"jwks_url":        emptyStringToNil(rec.JWKSURL),
		"subject_claim":   emptyStringToNil(rec.SubjectClaim),
		"username_claim":  emptyStringToNil(rec.UsernameClaim),
		"email_claim":     emptyStringToNil(rec.EmailClaim),
		"roles_claims":    rec.RolesClaims,
		"groups_claims":   rec.GroupsClaims,
		"created_at":      formatTimeValue(rec.CreatedAt),
		"updated_at":      formatTimeValue(rec.UpdatedAt),
	}
}
