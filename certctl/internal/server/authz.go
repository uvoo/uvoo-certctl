package server

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"certctl/internal/auth"
	"certctl/internal/storage"
	"certctl/internal/util"
)

type permissionResolver func(r *http.Request) (auth.PermissionRequest, bool)

func (s *Server) requireAdminPermission(next http.HandlerFunc, resolve permissionResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, ok := resolve(r)
		if !ok {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		identity, status, err := s.authenticateAdminRequest(r, req)
		if err != nil {
			if status == 0 {
				status = http.StatusUnauthorized
			}
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", s.adminWWWAuthenticate())
			}
			writeError(w, status, err.Error())
			return
		}

		next(w, r.WithContext(auth.WithIdentity(r.Context(), identity)))
	}
}

func (s *Server) requireMetricsPermission(next http.HandlerFunc, resolve permissionResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, ok := resolve(r)
		if !ok {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		identity, status, err := s.authenticateMetricsRequest(r, req)
		if err != nil {
			if status == 0 {
				status = http.StatusUnauthorized
			}
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", s.metricsWWWAuthenticate())
			}
			writeError(w, status, err.Error())
			return
		}

		next(w, r.WithContext(auth.WithIdentity(r.Context(), identity)))
	}
}

func (s *Server) authenticateAdminRequest(r *http.Request, req auth.PermissionRequest) (auth.Identity, int, error) {
	if identity, ok := s.basicIdentityFromRequest(r, s.cfg.AdminUsername, s.cfg.AdminPassword, "basic_admin"); ok {
		s.incrementAuthResult("allowed", identity.AuthMethod)
		return identity, 0, nil
	}

	token := bearerTokenFromRequest(r)
	if token == "" {
		s.incrementAuthResult("invalid", "unknown")
		return auth.Identity{}, http.StatusUnauthorized, auth.ErrMissingBearerToken
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		return auth.Identity{}, http.StatusInternalServerError, err
	}
	defer store.Close()

	issuers, err := store.ListAuthIssuers(true)
	if err != nil {
		return auth.Identity{}, http.StatusInternalServerError, err
	}
	identity, err := s.authVerifier.Verify(r.Context(), token, issuers)
	if err != nil {
		s.incrementAuthResult("invalid", "bearer")
		return auth.Identity{}, http.StatusUnauthorized, err
	}
	subjectRec, err := store.UpsertSubjectSeen(storage.Subject{
		ID:       util.NewID(),
		Issuer:   identity.Issuer,
		Subject:  identity.Subject,
		Status:   storage.SubjectStatusPending,
		Username: identity.Username,
		Email:    identity.Email,
		Roles:    identity.Roles,
		Groups:   identity.Groups,
	})
	if err != nil {
		return auth.Identity{}, http.StatusInternalServerError, err
	}
	preview, updatedSubjectRec, err := s.resolveBearerSubject(store, identity, subjectRec)
	if err != nil {
		return auth.Identity{}, http.StatusInternalServerError, err
	}
	subjectRec = updatedSubjectRec
	identity = preview.Identity
	if preview.Status == storage.SubjectStatusDisabled {
		s.incrementAuthResult("disabled", "bearer")
		return auth.Identity{}, http.StatusForbidden, auth.ErrSubjectDisabled
	}
	if preview.Status == storage.SubjectStatusPending {
		s.incrementAuthResult("pending", "bearer")
		return auth.Identity{}, http.StatusForbidden, auth.ErrSubjectPending
	}

	bindings, err := store.ListAuthzBindings(true)
	if err != nil {
		return auth.Identity{}, http.StatusInternalServerError, err
	}
	if !auth.Allowed(identity, bindings, req) {
		s.incrementAuthResult("forbidden", identity.AuthMethod)
		return auth.Identity{}, http.StatusForbidden, auth.ErrForbidden
	}
	s.incrementAuthResult("allowed", identity.AuthMethod)
	return identity, 0, nil
}

func (s *Server) authenticateMetricsRequest(r *http.Request, req auth.PermissionRequest) (auth.Identity, int, error) {
	if identity, ok := s.basicIdentityFromRequest(r, s.cfg.MetricsUsername, s.cfg.MetricsPassword, "basic_metrics"); ok {
		s.incrementAuthResult("allowed", identity.AuthMethod)
		return identity, 0, nil
	}
	if identity, ok := s.basicIdentityFromRequest(r, s.cfg.AdminUsername, s.cfg.AdminPassword, "basic_admin"); ok {
		s.incrementAuthResult("allowed", identity.AuthMethod)
		return identity, 0, nil
	}

	token := bearerTokenFromRequest(r)
	if token == "" {
		s.incrementAuthResult("invalid", "unknown")
		return auth.Identity{}, http.StatusUnauthorized, auth.ErrMissingBearerToken
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		return auth.Identity{}, http.StatusInternalServerError, err
	}
	defer store.Close()

	issuers, err := store.ListAuthIssuers(true)
	if err != nil {
		return auth.Identity{}, http.StatusInternalServerError, err
	}
	identity, err := s.authVerifier.Verify(r.Context(), token, issuers)
	if err != nil {
		s.incrementAuthResult("invalid", "bearer")
		return auth.Identity{}, http.StatusUnauthorized, err
	}
	subjectRec, err := store.UpsertSubjectSeen(storage.Subject{
		ID:       util.NewID(),
		Issuer:   identity.Issuer,
		Subject:  identity.Subject,
		Status:   storage.SubjectStatusPending,
		Username: identity.Username,
		Email:    identity.Email,
		Roles:    identity.Roles,
		Groups:   identity.Groups,
	})
	if err != nil {
		return auth.Identity{}, http.StatusInternalServerError, err
	}
	preview, updatedSubjectRec, err := s.resolveBearerSubject(store, identity, subjectRec)
	if err != nil {
		return auth.Identity{}, http.StatusInternalServerError, err
	}
	subjectRec = updatedSubjectRec
	identity = preview.Identity
	if preview.Status == storage.SubjectStatusDisabled {
		s.incrementAuthResult("disabled", "bearer")
		return auth.Identity{}, http.StatusForbidden, auth.ErrSubjectDisabled
	}
	if preview.Status == storage.SubjectStatusPending {
		s.incrementAuthResult("pending", "bearer")
		return auth.Identity{}, http.StatusForbidden, auth.ErrSubjectPending
	}

	bindings, err := store.ListAuthzBindings(true)
	if err != nil {
		return auth.Identity{}, http.StatusInternalServerError, err
	}
	if !auth.Allowed(identity, bindings, req) {
		s.incrementAuthResult("forbidden", identity.AuthMethod)
		return auth.Identity{}, http.StatusForbidden, auth.ErrForbidden
	}
	s.incrementAuthResult("allowed", identity.AuthMethod)
	return identity, 0, nil
}

func (s *Server) resolveBearerSubject(store *storage.Store, identity auth.Identity, subjectRec storage.Subject) (auth.SubjectAccessPreview, storage.Subject, error) {
	preview := auth.SubjectAccessPreview{
		Status:   subjectRec.Status,
		Reason:   "active",
		Identity: auth.ApplySubjectRecord(identity, subjectRec),
	}
	if subjectRec.Status == storage.SubjectStatusPending {
		rules, err := store.ListSubjectAutoApprovalRules(true)
		if err != nil {
			return auth.SubjectAccessPreview{}, storage.Subject{}, err
		}
		preview = auth.PreviewSubjectAccess(identity, &subjectRec, rules)
		if preview.Reason == "auto_approved" {
			if err := store.UpdateSubjectApproval(
				identity.Issuer,
				identity.Subject,
				storage.SubjectStatusActive,
				preview.Identity.LocalRoles,
				preview.Identity.LocalGroups,
			); err != nil {
				return auth.SubjectAccessPreview{}, storage.Subject{}, err
			}
			_ = store.LogAuditEvent(storage.AuditEvent{
				ID:         util.NewID(),
				Action:     "auto_approve_subject",
				TargetKind: "subject",
				TargetID:   subjectRec.ID,
				Summary:    identity.Issuer + " " + identity.Subject + " via rules " + strings.Join(preview.MatchedRuleNames, ","),
			})
			s.incrementAutoApprovalRules(preview.MatchedRuleNames)
			subjectRec, err = store.GetSubject(identity.Issuer, identity.Subject)
			if err != nil {
				return auth.SubjectAccessPreview{}, storage.Subject{}, err
			}
			preview = auth.PreviewSubjectAccess(identity, &subjectRec, nil)
		}
	}
	return preview, subjectRec, nil
}

func (s *Server) basicIdentityFromRequest(r *http.Request, expectedUser, expectedPass, authMethod string) (auth.Identity, bool) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return auth.Identity{}, false
	}
	if !secureCompare(user, expectedUser) || !secureCompare(pass, expectedPass) {
		return auth.Identity{}, false
	}
	if strings.TrimSpace(expectedUser) == "" || expectedPass == "" {
		return auth.Identity{}, false
	}
	identity := auth.SuperuserIdentity(user)
	identity.AuthMethod = authMethod
	return identity, true
}

func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func bearerTokenFromRequest(r *http.Request) string {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(raw) < 7 || !strings.EqualFold(raw[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(raw[7:])
}

func mergeStringSets(base []string, extra []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, item := range append(append([]string(nil), base...), extra...) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func (s *Server) adminWWWAuthenticate() string {
	return `Basic realm="certctl", Bearer realm="certctl"`
}

func (s *Server) metricsWWWAuthenticate() string {
	if strings.TrimSpace(s.cfg.MetricsUsername) != "" && s.cfg.MetricsPassword != "" {
		return `Basic realm="certctl-metrics", Bearer realm="certctl"`
	}
	return s.adminWWWAuthenticate()
}

func adminDoctorPermission(r *http.Request) (auth.PermissionRequest, bool) {
	if r.Method != http.MethodGet {
		return auth.PermissionRequest{}, false
	}
	return auth.PermissionRequest{Permission: "doctor.read"}, true
}

func adminEffectiveAuthzPermission(r *http.Request) (auth.PermissionRequest, bool) {
	if r.Method != http.MethodGet {
		return auth.PermissionRequest{}, false
	}
	return auth.PermissionRequest{Permission: "authz.read"}, true
}

func adminAuthIssuerPermission(r *http.Request) (auth.PermissionRequest, bool) {
	if r.Method != http.MethodGet {
		return auth.PermissionRequest{}, false
	}
	return auth.PermissionRequest{Permission: "auth_issuer.read"}, true
}

func metricsPermission(r *http.Request) (auth.PermissionRequest, bool) {
	if r.Method != http.MethodGet {
		return auth.PermissionRequest{}, false
	}
	return auth.PermissionRequest{Permission: "metrics.read"}, true
}

func adminCSRCollectionPermission(r *http.Request) (auth.PermissionRequest, bool) {
	switch r.Method {
	case http.MethodGet:
		return auth.PermissionRequest{Permission: "csr.read", ResourceKind: "csr_request", ResourceRef: "*"}, true
	case http.MethodPost:
		return auth.PermissionRequest{Permission: "csr.submit", ResourceKind: "csr_request", ResourceRef: "*"}, true
	default:
		return auth.PermissionRequest{}, false
	}
}

func adminCSRItemPermission(r *http.Request) (auth.PermissionRequest, bool) {
	id, action := adminCSRPathParts(r.URL.Path)
	if id == "" {
		return auth.PermissionRequest{}, false
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		return auth.PermissionRequest{Permission: "csr.read", ResourceKind: "csr_request", ResourceRef: id}, true
	case action == "approve" && r.Method == http.MethodPost:
		return auth.PermissionRequest{Permission: "csr.approve", ResourceKind: "csr_request", ResourceRef: id}, true
	case action == "reject" && r.Method == http.MethodPost:
		return auth.PermissionRequest{Permission: "csr.reject", ResourceKind: "csr_request", ResourceRef: id}, true
	default:
		return auth.PermissionRequest{}, false
	}
}

func adminSubjectCollectionPermission(r *http.Request) (auth.PermissionRequest, bool) {
	if r.Method != http.MethodGet {
		return auth.PermissionRequest{}, false
	}
	return auth.PermissionRequest{Permission: "subject.read", ResourceKind: "subject", ResourceRef: "*"}, true
}

func adminSubjectItemPermission(r *http.Request) (auth.PermissionRequest, bool) {
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/approve"):
		return auth.PermissionRequest{Permission: "subject.approve", ResourceKind: "subject", ResourceRef: "*"}, true
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/update"):
		return auth.PermissionRequest{Permission: "subject.update", ResourceKind: "subject", ResourceRef: "*"}, true
	default:
		return auth.PermissionRequest{}, false
	}
}

func adminSubjectAutoApprovalCollectionPermission(r *http.Request) (auth.PermissionRequest, bool) {
	if r.Method != http.MethodGet {
		return auth.PermissionRequest{}, false
	}
	return auth.PermissionRequest{Permission: "subject_auto_approval.read", ResourceKind: "subject_auto_approval_rule", ResourceRef: "*"}, true
}

func adminSubjectAutoApprovalItemPermission(r *http.Request) (auth.PermissionRequest, bool) {
	name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/admin/v1/subject-auto-approvals/"))
	if name == "" {
		return auth.PermissionRequest{}, false
	}
	switch r.Method {
	case http.MethodGet:
		return auth.PermissionRequest{Permission: "subject_auto_approval.read", ResourceKind: "subject_auto_approval_rule", ResourceRef: name}, true
	case http.MethodPut, http.MethodDelete:
		return auth.PermissionRequest{Permission: "subject_auto_approval.write", ResourceKind: "subject_auto_approval_rule", ResourceRef: name}, true
	default:
		return auth.PermissionRequest{}, false
	}
}
