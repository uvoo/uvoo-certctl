package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"certctl/internal/auth"
	"certctl/internal/cli"
	"certctl/internal/storage"
	"certctl/internal/util"
)

type Config struct {
	DBPath                  string
	Listen                  string
	TLSCertFile             string
	TLSKeyFile              string
	AllowCIDRs              []string
	CSRSubmitPassword       string
	CSRMaxBodyBytes         int64
	CSRMinInterval          time.Duration
	AdminUsername           string
	AdminPassword           string
	MetricsUsername         string
	MetricsPassword         string
	AdminWarnDays           int
	DefaultIntermediateName string
	ProviderHTTPTimeout     time.Duration
	EnableMetrics           bool
}

type Server struct {
	cfg           Config
	mux           *http.ServeMux
	mu            sync.Mutex
	csrLastSubmit map[string]time.Time
	authResults   map[string]int
	autoApprovals map[string]int
	issuerProbes  map[string]issuerProbeStatus
	allowNets     []*net.IPNet
	configErr     error
	authVerifier  *auth.Verifier
}

type issuerProbeStatus struct {
	Status    string
	Message   string
	CheckedAt time.Time
}

func New(cfg Config) *Server {
	s := &Server{
		cfg:           cfg,
		mux:           http.NewServeMux(),
		csrLastSubmit: map[string]time.Time{},
		authResults:   map[string]int{},
		autoApprovals: map[string]int{},
		issuerProbes:  map[string]issuerProbeStatus{},
		authVerifier:  auth.NewVerifier(cfg.ProviderHTTPTimeout),
	}
	if s.cfg.CSRMaxBodyBytes <= 0 {
		s.cfg.CSRMaxBodyBytes = 1 << 20
	}
	if s.cfg.CSRMinInterval <= 0 {
		s.cfg.CSRMinInterval = 2 * time.Second
	}
	s.allowNets, s.configErr = parseAllowCIDRs(s.cfg.AllowCIDRs)

	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/share/", s.handleShare)
	s.mux.HandleFunc("/csr-requests", s.handleCSRRequests)
	s.mux.HandleFunc("/csr-requests/", s.handleCSRRequests)
	s.mux.HandleFunc("/admin/v1/doctor", s.requireAdminPermission(s.handleAdminDoctor, adminDoctorPermission))
	s.mux.HandleFunc("/admin/v1/doctor/auth", s.requireAdminPermission(s.handleAdminAuthDoctor, adminDoctorPermission))
	s.mux.HandleFunc("/admin/v1/effective-authz", s.requireAdminPermission(s.handleAdminEffectiveAuthz, adminEffectiveAuthzPermission))
	s.mux.HandleFunc("/admin/v1/auth-issuers", s.requireAdminPermission(s.handleAdminAuthIssuers, adminAuthIssuerPermission))
	s.mux.HandleFunc("/admin/v1/auth-issuers/", s.requireAdminPermission(s.handleAdminAuthIssuers, adminAuthIssuerPermission))
	s.mux.HandleFunc("/admin/v1/authz-bindings", s.requireAdminPermission(s.handleAdminAuthzBindings, adminEffectiveAuthzPermission))
	s.mux.HandleFunc("/admin/v1/authz-bindings/", s.requireAdminPermission(s.handleAdminAuthzBindings, adminEffectiveAuthzPermission))
	s.mux.HandleFunc("/admin/v1/csr-requests", s.requireAdminPermission(s.handleAdminCSRRequests, adminCSRCollectionPermission))
	s.mux.HandleFunc("/admin/v1/csr-requests/", s.requireAdminPermission(s.handleAdminCSRRequests, adminCSRItemPermission))
	s.mux.HandleFunc("/admin/v1/subjects", s.requireAdminPermission(s.handleAdminSubjects, adminSubjectCollectionPermission))
	s.mux.HandleFunc("/admin/v1/subjects/", s.requireAdminPermission(s.handleAdminSubjects, adminSubjectItemPermission))
	s.mux.HandleFunc("/admin/v1/subject-auto-approvals", s.requireAdminPermission(s.handleAdminSubjectAutoApprovals, adminSubjectAutoApprovalCollectionPermission))
	s.mux.HandleFunc("/admin/v1/subject-auto-approvals/", s.requireAdminPermission(s.handleAdminSubjectAutoApprovals, adminSubjectAutoApprovalItemPermission))
	if s.cfg.EnableMetrics {
		s.mux.Handle("/metrics", s.requireMetricsPermission(s.handleMetrics, metricsPermission))
	}

	return s
}

func (s *Server) Run() error {
	if s.configErr != nil {
		return s.configErr
	}
	if err := validateTLSFiles(s.cfg.TLSCertFile, s.cfg.TLSKeyFile); err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	if strings.TrimSpace(s.cfg.TLSCertFile) != "" {
		return httpSrv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	}
	return httpSrv.ListenAndServe()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.configErr != nil {
		writeError(w, http.StatusInternalServerError, "server configuration error")
		return
	}
	if !s.allowRemote(r.RemoteAddr) {
		writeError(w, http.StatusForbidden, "remote address is not allowed by nacl")
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) incrementAuthResult(result, authMethod string) {
	result = strings.TrimSpace(result)
	authMethod = strings.TrimSpace(authMethod)
	if result == "" {
		return
	}
	if authMethod == "" {
		authMethod = "unknown"
	}
	key := result + "|" + authMethod
	s.mu.Lock()
	s.authResults[key]++
	s.mu.Unlock()
}

func (s *Server) incrementAutoApprovalRules(ruleNames []string) {
	s.mu.Lock()
	for _, ruleName := range ruleNames {
		ruleName = strings.TrimSpace(ruleName)
		if ruleName == "" {
			continue
		}
		s.autoApprovals[ruleName]++
	}
	s.mu.Unlock()
}

func (s *Server) authResultSnapshot() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.authResults))
	for key, value := range s.authResults {
		out[key] = value
	}
	return out
}

func (s *Server) autoApprovalSnapshot() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.autoApprovals))
	for key, value := range s.autoApprovals {
		out[key] = value
	}
	return out
}

func (s *Server) recordIssuerProbe(issuer string, err error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return
	}
	status := issuerProbeStatus{
		Status:    "ok",
		CheckedAt: time.Now().UTC(),
	}
	if err != nil {
		status.Status = "error"
		status.Message = err.Error()
	}
	s.mu.Lock()
	s.issuerProbes[issuer] = status
	s.mu.Unlock()
}

func (s *Server) issuerProbeSnapshot() map[string]issuerProbeStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]issuerProbeStatus, len(s.issuerProbes))
	for key, value := range s.issuerProbes {
		out[key] = value
	}
	return out
}

func (s *Server) probeAuthIssuer(ctx context.Context, issuer storage.AuthIssuer) error {
	err := s.authVerifier.CheckIssuerConnectivity(ctx, issuer)
	s.recordIssuerProbe(issuer.Issuer, err)
	return err
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}

func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	token, subpath := parseSharePath(r.URL.Path)
	if token == "" {
		writeError(w, http.StatusNotFound, "share token not found")
		return
	}

	store, err := storage.Open(s.cfg.DBPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open database")
		return
	}
	defer store.Close()

	share, err := store.GetShareByToken(token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "share not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load share")
		return
	}

	if isRevoked(share) {
		writeError(w, http.StatusForbidden, "share revoked")
		return
	}
	if isExpired(share) {
		writeError(w, http.StatusForbidden, "share expired")
		return
	}
	if maxViewsReached(share) {
		writeError(w, http.StatusForbidden, "share view limit reached")
		return
	}

	switch {
	case r.Method == http.MethodGet && subpath == "":
		s.handleShareMetadata(w, r, store, share)
		return
	case r.Method == http.MethodPost && subpath == "/access":
		s.handleShareAccess(w, r, store, share)
		return
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
}

func (s *Server) handleShareMetadata(w http.ResponseWriter, r *http.Request, store *storage.Store, share storage.CertShare) {
	resp := map[string]any{
		"share_id":              share.ID,
		"cert_kind":             share.CertKind,
		"mode":                  share.Mode,
		"expires_at":            formatTime(share.ExpiresAt),
		"requires_access":       true,
		"requires_key_password": share.Mode == "cert_key",
		"view_count":            share.ViewCount,
		"max_views":             nullableInt64(share.MaxViews),
		"note":                  share.Note,
	}

	switch share.CertKind {
	case storage.CertKindPublic:
		rec, err := store.GetByID(share.CertID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load certificate")
			return
		}
		resp["common_name"] = rec.CommonName
		resp["sans_csv"] = rec.SANsCSV
		resp["provider"] = rec.Provider
		resp["issuer"] = rec.Issuer
		resp["status"] = rec.Status
		resp["not_before"] = formatTime(rec.NotBefore)
		resp["not_after"] = formatTime(rec.NotAfter)

	case storage.CertKindPrivate:
		rec, err := store.GetPrivateCertByID(share.CertID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load certificate")
			return
		}
		resp["common_name"] = rec.CommonName
		resp["sans_csv"] = rec.SANsCSV
		resp["issuer"] = rec.Issuer
		resp["status"] = rec.Status
		resp["cert_type"] = rec.CertType
		resp["key_type"] = rec.KeyType
		resp["not_before"] = formatTime(rec.NotBefore)
		resp["not_after"] = formatTime(rec.NotAfter)

	default:
		writeError(w, http.StatusInternalServerError, "unsupported certificate share kind")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

type accessRequest struct {
	SharePassword string `json:"share_password"`
	KeyPassword   string `json:"key_password"`
	Password      string `json:"password"` // cert encryption password for private key decrypt
}

type accessResponse struct {
	ShareID        string `json:"share_id"`
	CertKind       string `json:"cert_kind"`
	CertID         string `json:"cert_id"`
	CommonName     string `json:"common_name"`
	SANsCSV        string `json:"sans_csv"`
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
}

func (s *Server) handleShareAccess(w http.ResponseWriter, r *http.Request, store *storage.Store, share storage.CertShare) {
	var req accessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if err := util.CheckPassword(share.SharePasswordHash, req.SharePassword); err != nil {
		writeError(w, http.StatusForbidden, "invalid share password")
		return
	}

	resp := accessResponse{
		ShareID:  share.ID,
		CertKind: share.CertKind,
	}

	switch share.CertKind {
	case storage.CertKindPublic:
		rec, err := store.GetByID(share.CertID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load certificate")
			return
		}
		resp.CertID = rec.ID
		resp.CommonName = rec.CommonName
		resp.SANsCSV = rec.SANsCSV
		resp.CertificatePEM = string(rec.CertPEM)

	case storage.CertKindPrivate:
		rec, err := store.GetPrivateCertByID(share.CertID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load certificate")
			return
		}
		resp.CertID = rec.ID
		resp.CommonName = rec.CommonName
		resp.SANsCSV = rec.SANsCSV
		resp.CertificatePEM = string(rec.CertPEM)

		if share.Mode == "cert_key" {
			if !privateKeyStored(rec.KeyPEM) {
				writeError(w, http.StatusForbidden, "private key is not stored for csr-based private certificate")
				return
			}
			if strings.TrimSpace(req.KeyPassword) == "" {
				writeError(w, http.StatusForbidden, "key password required")
				return
			}
			if err := util.CheckPassword(share.KeyPasswordHash, req.KeyPassword); err != nil {
				writeError(w, http.StatusForbidden, "invalid key password")
				return
			}
			keyPEM, err := cli.Decrypt(rec.KeyPEM, req.Password)
			if err != nil {
				writeError(w, http.StatusForbidden, "failed to decrypt private key with provided password")
				return
			}
			resp.PrivateKeyPEM = string(keyPEM)
		}

	default:
		writeError(w, http.StatusInternalServerError, "unsupported certificate share kind")
		return
	}

	if err := store.IncrementShareView(share.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update share view count")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func parseSharePath(path string) (token string, subpath string) {
	trimmed := strings.TrimPrefix(path, "/share/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return "", ""
	}

	parts := strings.Split(trimmed, "/")
	token = parts[0]
	if len(parts) > 1 {
		subpath = "/" + strings.Join(parts[1:], "/")
	}
	return token, subpath
}

func isExpired(sh storage.CertShare) bool {
	return !sh.ExpiresAt.IsZero() && time.Now().UTC().After(sh.ExpiresAt)
}

func isRevoked(sh storage.CertShare) bool {
	return !sh.RevokedAt.IsZero()
}

func maxViewsReached(sh storage.CertShare) bool {
	return sh.MaxViews.Valid && int64(sh.ViewCount) >= sh.MaxViews.Int64
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func formatTimeValue(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func nullableInt64(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}

func (s *Server) allowCSRSubmit(remoteAddr string) (time.Duration, bool) {
	if s.cfg.CSRMinInterval <= 0 {
		return 0, true
	}

	key := remoteKey(remoteAddr)
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	if last, ok := s.csrLastSubmit[key]; ok {
		wait := s.cfg.CSRMinInterval - now.Sub(last)
		if wait > 0 {
			return wait, false
		}
	}
	s.csrLastSubmit[key] = now
	return 0, true
}

func remoteKey(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && strings.TrimSpace(host) != "" {
		return host
	}
	return remoteAddr
}

func (s *Server) allowRemote(remoteAddr string) bool {
	if len(s.allowNets) == 0 {
		return true
	}

	ip := remoteIP(remoteAddr)
	if ip == nil {
		return false
	}
	for _, network := range s.allowNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteIP(remoteAddr string) net.IP {
	host := remoteKey(remoteAddr)
	if host == "" || host == "unknown" {
		return nil
	}
	return net.ParseIP(host)
}

func parseAllowCIDRs(values []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid nacl cidr %q: %w", value, err)
		}
		nets = append(nets, network)
	}
	return nets, nil
}

func validateTLSFiles(certFile, keyFile string) error {
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	switch {
	case certFile == "" && keyFile == "":
		return nil
	case certFile == "" || keyFile == "":
		return errors.New("both --tls-cert-file and --tls-key-file are required to enable https")
	default:
		return nil
	}
}

func privateKeyStored(keyPEM []byte) bool {
	return len(bytes.TrimSpace(keyPEM)) > 0
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{
		"error": msg,
	})
}
