package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"certctl/internal/cli"
	"certctl/internal/storage"
	"certctl/internal/util"
)

type Config struct {
	DBPath            string
	Listen            string
	CSRSubmitPassword string
}

type Server struct {
	cfg Config
	mux *http.ServeMux
}

func New(cfg Config) *Server {
	s := &Server{
		cfg: cfg,
		mux: http.NewServeMux(),
	}

	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/share/", s.handleShare)
	s.mux.HandleFunc("/csr-requests", s.handleCSRRequests)
	s.mux.HandleFunc("/csr-requests/", s.handleCSRRequests)

	return s
}

func (s *Server) Run() error {
	httpSrv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return httpSrv.ListenAndServe()
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

func nullableInt64(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
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
