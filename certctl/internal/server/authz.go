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
				w.Header().Set("WWW-Authenticate", `Basic realm="certctl", Bearer realm="certctl"`)
			}
			writeError(w, status, err.Error())
			return
		}

		next(w, r.WithContext(auth.WithIdentity(r.Context(), identity)))
	}
}

func (s *Server) authenticateAdminRequest(r *http.Request, req auth.PermissionRequest) (auth.Identity, int, error) {
	if identity, ok := s.basicIdentityFromRequest(r); ok {
		return identity, 0, nil
	}

	token := bearerTokenFromRequest(r)
	if token == "" {
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
	if subjectRec.Status == storage.SubjectStatusPending {
		rules, err := store.ListSubjectAutoApprovalRules(true)
		if err != nil {
			return auth.Identity{}, http.StatusInternalServerError, err
		}
		match := auth.MatchSubjectAutoApprovalRules(identity, rules)
		if len(match.RuleNames) > 0 {
			if err := store.UpdateSubjectApproval(
				identity.Issuer,
				identity.Subject,
				storage.SubjectStatusActive,
				mergeStringSets(subjectRec.LocalRoles, match.LocalRoles),
				mergeStringSets(subjectRec.LocalGroups, match.LocalGroups),
			); err != nil {
				return auth.Identity{}, http.StatusInternalServerError, err
			}
			_ = store.LogAuditEvent(storage.AuditEvent{
				ID:         util.NewID(),
				Action:     "auto_approve_subject",
				TargetKind: "subject",
				TargetID:   subjectRec.ID,
				Summary:    identity.Issuer + " " + identity.Subject + " via rules " + strings.Join(match.RuleNames, ","),
			})
			subjectRec, err = store.GetSubject(identity.Issuer, identity.Subject)
			if err != nil {
				return auth.Identity{}, http.StatusInternalServerError, err
			}
		}
	}
	identity = auth.ApplySubjectRecord(identity, subjectRec)
	if subjectRec.Status == storage.SubjectStatusDisabled {
		return auth.Identity{}, http.StatusForbidden, auth.ErrSubjectDisabled
	}
	if subjectRec.Status == storage.SubjectStatusPending {
		return auth.Identity{}, http.StatusForbidden, auth.ErrSubjectPending
	}

	bindings, err := store.ListAuthzBindings(true)
	if err != nil {
		return auth.Identity{}, http.StatusInternalServerError, err
	}
	if !auth.Allowed(identity, bindings, req) {
		return auth.Identity{}, http.StatusForbidden, auth.ErrForbidden
	}
	return identity, 0, nil
}

func (s *Server) basicIdentityFromRequest(r *http.Request) (auth.Identity, bool) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return auth.Identity{}, false
	}
	if !secureCompare(user, s.cfg.AdminUsername) || !secureCompare(pass, s.cfg.AdminPassword) {
		return auth.Identity{}, false
	}
	if strings.TrimSpace(s.cfg.AdminUsername) == "" || s.cfg.AdminPassword == "" {
		return auth.Identity{}, false
	}
	return auth.SuperuserIdentity(user), true
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

func adminDoctorPermission(r *http.Request) (auth.PermissionRequest, bool) {
	if r.Method != http.MethodGet {
		return auth.PermissionRequest{}, false
	}
	return auth.PermissionRequest{Permission: "doctor.read"}, true
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
