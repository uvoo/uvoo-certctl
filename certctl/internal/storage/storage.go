package storage

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	CertKindPublic  = "public"
	CertKindPrivate = "private"

	StatusActive     = "active"
	StatusSuperseded = "superseded"
	StatusRevoked    = "revoked"
	StatusExpired    = "expired"
	StatusRetired    = "retired"
)

type Store struct{ db *sql.DB }

type PublicCert struct {
	ID               string
	CommonName       string
	SANsCSV          string
	SANsHash         string
	CertPEM          []byte
	KeyPEM           []byte
	Provider         string
	Email            string
	Issuer           string
	Status           string
	SupersedesCertID string
	RevokedAt        time.Time
	NotBefore        time.Time
	NotAfter         time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type CertShare struct {
	ID                string
	CertKind          string
	CertID            string
	ShareToken        string
	Mode              string
	SharePasswordHash string
	KeyPasswordHash   string
	ExpiresAt         time.Time
	MaxViews          sql.NullInt64
	ViewCount         int
	CreatedAt         time.Time
	LastViewedAt      time.Time
	RevokedAt         time.Time
	Note              string
}

type PrivateRootCA struct {
	ID             string
	Name           string
	CommonName     string
	Generation     int
	Status         string
	IsTrusted      bool
	IsIssuing      bool
	SupersedesCAID string
	KeyType        string
	CertPEM        []byte
	KeyPEM         []byte
	Issuer         string
	NotBefore      time.Time
	NotAfter       time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type PrivateIntermediateCA struct {
	ID             string
	RootCAID       string
	Name           string
	CommonName     string
	Generation     int
	Status         string
	IsTrusted      bool
	IsIssuing      bool
	SupersedesCAID string
	KeyType        string
	CertPEM        []byte
	KeyPEM         []byte
	Issuer         string
	NotBefore      time.Time
	NotAfter       time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type PrivateCert struct {
	ID               string
	IntermediateCAID string
	CommonName       string
	SANsCSV          string
	CertType         string
	KeyType          string
	CertPEM          []byte
	KeyPEM           []byte
	Issuer           string
	Status           string
	SupersedesCertID string
	RevokedAt        time.Time
	NotBefore        time.Time
	NotAfter         time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type scanner interface {
	Scan(dest ...any) error
}

func Open(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := ensureSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := syncDerivedStatuses(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ParseCertMetadata(certPEM []byte) (issuer string, notBefore, notAfter time.Time, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", time.Time{}, time.Time{}, fmt.Errorf("failed to parse PEM block from certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.Issuer.String(), cert.NotBefore.UTC(), cert.NotAfter.UTC(), nil
}

func NormalizeSANs(sans []string) (normalized []string, csv string, hash string) {
	set := map[string]struct{}{}
	for _, s := range sans {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		set[s] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)

	csv = strings.Join(out, ",")
	sum := sha256.Sum256([]byte(csv))
	hash = hex.EncodeToString(sum[:])
	return out, csv, hash
}

func (s *Store) Upsert(rec PublicCert) error {
	if strings.TrimSpace(rec.CommonName) == "" {
		return fmt.Errorf("record common_name is required")
	}
	if rec.SANsCSV == "" || rec.SANsHash == "" {
		return fmt.Errorf("record sans_csv and sans_hash are required")
	}
	if rec.ID == "" {
		return fmt.Errorf("record id is required")
	}

	return withTx(s.db, func(tx *sql.Tx) error {
		if err := syncDerivedStatusesTx(tx); err != nil {
			return err
		}

		if current, err := getActivePublicCertTx(tx, rec.CommonName); err == nil {
			rec.SupersedesCertID = current.ID
			if _, err := tx.Exec(
				`UPDATE public_certs SET status = ?, updated_at = ? WHERE common_name = ? AND status = ?`,
				StatusSuperseded,
				nowRFC3339(),
				rec.CommonName,
				StatusActive,
			); err != nil {
				return err
			}
		} else if err != sql.ErrNoRows {
			return err
		}

		rec.Status = defaultLeafStatus(rec.Status)
		rec.CreatedAt = defaultCreatedAt(rec.CreatedAt)
		rec.UpdatedAt = time.Now().UTC()

		_, err := tx.Exec(`
			INSERT INTO public_certs
			(id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, status, supersedes_cert_id, revoked_at, not_before, not_after, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			rec.ID,
			rec.CommonName,
			rec.SANsCSV,
			rec.SANsHash,
			rec.CertPEM,
			rec.KeyPEM,
			nullIfEmpty(rec.Provider),
			nullIfEmpty(rec.Email),
			nullIfEmpty(rec.Issuer),
			rec.Status,
			nullIfEmpty(rec.SupersedesCertID),
			timeOrEmpty(rec.RevokedAt),
			timeOrEmpty(rec.NotBefore),
			timeOrEmpty(rec.NotAfter),
			timeOrNil(rec.CreatedAt),
			timeOrNil(rec.UpdatedAt),
		)
		return err
	})
}

func (s *Store) Get(commonName string) (PublicCert, error) {
	var rec PublicCert
	err := scanPublicCert(s.db.QueryRow(`
		SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, status,
		       COALESCE(supersedes_cert_id, ''), revoked_at, not_before, not_after, created_at, updated_at
		FROM public_certs
		WHERE common_name = ? AND status = ?
		ORDER BY created_at DESC
		LIMIT 1
	`, commonName, StatusActive), &rec)
	return rec, err
}

func (s *Store) List(name string, includeInactive bool) ([]PublicCert, error) {
	var (
		rows *sql.Rows
		err  error
	)

	args := []any{}
	var where []string
	if strings.TrimSpace(name) != "" {
		where = append(where, "(common_name = ? OR sans_csv LIKE ?)")
		args = append(args, name, "%"+name+"%")
	}
	if !includeInactive {
		where = append(where, "status = ?")
		args = append(args, StatusActive)
	}

	query := `
		SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, status,
		       COALESCE(supersedes_cert_id, ''), revoked_at, not_before, not_after, created_at, updated_at
		FROM public_certs
	`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY common_name, created_at DESC"

	rows, err = s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PublicCert
	for rows.Next() {
		var rec PublicCert
		if err := scanPublicCert(rows, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) GetByCommonName(name string) (PublicCert, error) {
	return s.Get(name)
}

func (s *Store) GetBySAN(name string) (PublicCert, error) {
	var rec PublicCert
	err := scanPublicCert(s.db.QueryRow(`
		SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, status,
		       COALESCE(supersedes_cert_id, ''), revoked_at, not_before, not_after, created_at, updated_at
		FROM public_certs
		WHERE status = ?
		  AND (
			common_name = ?
			OR sans_csv = ?
			OR sans_csv LIKE ?
			OR sans_csv LIKE ?
			OR sans_csv LIKE ?
		  )
		ORDER BY created_at DESC
		LIMIT 1
	`,
		StatusActive,
		name,
		name,
		name+",%",
		"%,"+name+",%",
		"%,"+name,
	), &rec)
	return rec, err
}

func (s *Store) FindByHash(commonName, hash string) (PublicCert, error) {
	var rec PublicCert
	err := scanPublicCert(s.db.QueryRow(`
		SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, status,
		       COALESCE(supersedes_cert_id, ''), revoked_at, not_before, not_after, created_at, updated_at
		FROM public_certs
		WHERE common_name = ? AND sans_hash = ? AND status = ?
		ORDER BY created_at DESC
		LIMIT 1
	`, commonName, hash, StatusActive), &rec)
	return rec, err
}

func (s *Store) GetByID(id string) (PublicCert, error) {
	var rec PublicCert
	err := scanPublicCert(s.db.QueryRow(`
		SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, status,
		       COALESCE(supersedes_cert_id, ''), revoked_at, not_before, not_after, created_at, updated_at
		FROM public_certs
		WHERE id = ?
		LIMIT 1
	`, id), &rec)
	return rec, err
}

func (s *Store) CreateShare(sh CertShare) error {
	sh.CertKind = strings.ToLower(strings.TrimSpace(sh.CertKind))

	if sh.ID == "" {
		return fmt.Errorf("share id is required")
	}
	if sh.CertKind != CertKindPublic && sh.CertKind != CertKindPrivate {
		return fmt.Errorf("cert_kind must be %q or %q", CertKindPublic, CertKindPrivate)
	}
	if strings.TrimSpace(sh.CertID) == "" {
		return fmt.Errorf("cert_id is required")
	}
	if strings.TrimSpace(sh.ShareToken) == "" {
		return fmt.Errorf("share_token is required")
	}
	if sh.Mode != "cert" && sh.Mode != "cert_key" {
		return fmt.Errorf("mode must be cert or cert_key")
	}
	if strings.TrimSpace(sh.SharePasswordHash) == "" {
		return fmt.Errorf("share_password_hash is required")
	}
	if sh.CertKind == CertKindPublic && sh.Mode == "cert_key" {
		return fmt.Errorf("public certificate shares cannot use mode=cert_key")
	}

	switch sh.CertKind {
	case CertKindPublic:
		if _, err := s.GetByID(sh.CertID); err != nil {
			return fmt.Errorf("public certificate %q not found: %w", sh.CertID, err)
		}
	case CertKindPrivate:
		if _, err := s.GetPrivateCertByID(sh.CertID); err != nil {
			return fmt.Errorf("private certificate %q not found: %w", sh.CertID, err)
		}
	}

	_, err := s.db.Exec(`
		INSERT INTO cert_shares
		(id, cert_kind, cert_id, share_token, mode, share_password_hash, key_password_hash, expires_at, max_views, view_count, note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
	`,
		sh.ID,
		sh.CertKind,
		sh.CertID,
		sh.ShareToken,
		sh.Mode,
		sh.SharePasswordHash,
		nullIfEmpty(sh.KeyPasswordHash),
		timeOrEmpty(sh.ExpiresAt),
		nullInt64Value(sh.MaxViews),
		nullIfEmpty(sh.Note),
	)
	return err
}

func (s *Store) ListShares(certID string) ([]CertShare, error) {
	var (
		rows *sql.Rows
		err  error
	)

	if certID != "" {
		rows, err = s.db.Query(`
			SELECT id, cert_kind, cert_id, share_token, mode, share_password_hash, COALESCE(key_password_hash, ''),
			       expires_at, max_views, view_count, created_at, last_viewed_at, revoked_at, COALESCE(note, '')
			FROM cert_shares
			WHERE cert_id = ?
			ORDER BY created_at DESC
		`, certID)
	} else {
		rows, err = s.db.Query(`
			SELECT id, cert_kind, cert_id, share_token, mode, share_password_hash, COALESCE(key_password_hash, ''),
			       expires_at, max_views, view_count, created_at, last_viewed_at, revoked_at, COALESCE(note, '')
			FROM cert_shares
			ORDER BY created_at DESC
		`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CertShare
	for rows.Next() {
		var sh CertShare
		var expiresAt, createdAt, lastViewedAt, revokedAt sql.NullString
		var maxViews sql.NullInt64

		if err := rows.Scan(
			&sh.ID,
			&sh.CertKind,
			&sh.CertID,
			&sh.ShareToken,
			&sh.Mode,
			&sh.SharePasswordHash,
			&sh.KeyPasswordHash,
			&expiresAt,
			&maxViews,
			&sh.ViewCount,
			&createdAt,
			&lastViewedAt,
			&revokedAt,
			&sh.Note,
		); err != nil {
			return nil, err
		}

		sh.ExpiresAt = parseRFC3339Null(expiresAt)
		sh.CreatedAt = parseRFC3339Null(createdAt)
		sh.LastViewedAt = parseRFC3339Null(lastViewedAt)
		sh.RevokedAt = parseRFC3339Null(revokedAt)
		sh.MaxViews = maxViews

		out = append(out, sh)
	}

	return out, rows.Err()
}

func (s *Store) GetShareByToken(token string) (CertShare, error) {
	var sh CertShare
	var expiresAt, createdAt, lastViewedAt, revokedAt sql.NullString
	var maxViews sql.NullInt64

	err := s.db.QueryRow(`
		SELECT id, cert_kind, cert_id, share_token, mode, share_password_hash, COALESCE(key_password_hash, ''),
		       expires_at, max_views, view_count, created_at, last_viewed_at, revoked_at, COALESCE(note, '')
		FROM cert_shares
		WHERE share_token = ?
		LIMIT 1
	`, token).Scan(
		&sh.ID,
		&sh.CertKind,
		&sh.CertID,
		&sh.ShareToken,
		&sh.Mode,
		&sh.SharePasswordHash,
		&sh.KeyPasswordHash,
		&expiresAt,
		&maxViews,
		&sh.ViewCount,
		&createdAt,
		&lastViewedAt,
		&revokedAt,
		&sh.Note,
	)
	if err != nil {
		return sh, err
	}

	sh.ExpiresAt = parseRFC3339Null(expiresAt)
	sh.CreatedAt = parseRFC3339Null(createdAt)
	sh.LastViewedAt = parseRFC3339Null(lastViewedAt)
	sh.RevokedAt = parseRFC3339Null(revokedAt)
	sh.MaxViews = maxViews
	return sh, nil
}

func (s *Store) IncrementShareView(id string) error {
	_, err := s.db.Exec(`
		UPDATE cert_shares
		SET view_count = view_count + 1,
		    last_viewed_at = ?
		WHERE id = ?
	`, nowRFC3339(), id)
	return err
}

func (s *Store) RevokeShare(id string) error {
	_, err := s.db.Exec(`
		UPDATE cert_shares
		SET revoked_at = ?
		WHERE id = ?
	`, nowRFC3339(), id)
	return err
}

func (s *Store) UpsertPrivateRootCA(rec PrivateRootCA) error {
	if rec.ID == "" {
		return fmt.Errorf("root CA id is required")
	}
	if strings.TrimSpace(rec.Name) == "" {
		return fmt.Errorf("root CA name is required")
	}

	return withTx(s.db, func(tx *sql.Tx) error {
		if err := syncDerivedStatusesTx(tx); err != nil {
			return err
		}

		generation, err := nextGenerationTx(tx, "private_root_cas", rec.Name)
		if err != nil {
			return err
		}
		rec.Generation = generation
		rec.Status = defaultCAStatus(rec.Status)
		if !rec.IsTrusted {
			rec.IsTrusted = true
		}
		if !rec.IsIssuing {
			rec.IsIssuing = true
		}

		if current, err := getActivePrivateRootCAByNameTx(tx, rec.Name); err == nil {
			rec.SupersedesCAID = current.ID
			if _, err := tx.Exec(`
				UPDATE private_root_cas
				SET status = ?, is_issuing = 0, updated_at = ?
				WHERE name = ? AND status = ?
			`, StatusRetired, nowRFC3339(), rec.Name, StatusActive); err != nil {
				return err
			}
		} else if err != sql.ErrNoRows {
			return err
		}

		rec.CreatedAt = defaultCreatedAt(rec.CreatedAt)
		rec.UpdatedAt = time.Now().UTC()

		_, err = tx.Exec(`
			INSERT INTO private_root_cas
			(id, name, common_name, generation, status, is_trusted, is_issuing, supersedes_ca_id, key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			rec.ID,
			rec.Name,
			rec.CommonName,
			rec.Generation,
			rec.Status,
			boolToInt(rec.IsTrusted),
			boolToInt(rec.IsIssuing),
			nullIfEmpty(rec.SupersedesCAID),
			rec.KeyType,
			rec.CertPEM,
			rec.KeyPEM,
			nullIfEmpty(rec.Issuer),
			timeOrEmpty(rec.NotBefore),
			timeOrEmpty(rec.NotAfter),
			timeOrNil(rec.CreatedAt),
			timeOrNil(rec.UpdatedAt),
		)
		return err
	})
}

func (s *Store) GetPrivateRootCAByID(id string) (PrivateRootCA, error) {
	var rec PrivateRootCA
	err := scanPrivateRootCA(s.db.QueryRow(`
		SELECT id, name, common_name, generation, status, is_trusted, is_issuing, COALESCE(supersedes_ca_id, ''),
		       key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
		FROM private_root_cas
		WHERE id = ?
		LIMIT 1
	`, id), &rec)
	return rec, err
}

func (s *Store) GetIssuingPrivateRootCAByName(name string) (PrivateRootCA, error) {
	var rec PrivateRootCA
	err := scanPrivateRootCA(s.db.QueryRow(`
		SELECT id, name, common_name, generation, status, is_trusted, is_issuing, COALESCE(supersedes_ca_id, ''),
		       key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
		FROM private_root_cas
		WHERE name = ? AND status = ? AND is_issuing = 1
		ORDER BY generation DESC
		LIMIT 1
	`, name, StatusActive), &rec)
	return rec, err
}

func (s *Store) UpsertPrivateIntermediateCA(rec PrivateIntermediateCA) error {
	if rec.ID == "" {
		return fmt.Errorf("intermediate CA id is required")
	}
	if strings.TrimSpace(rec.Name) == "" {
		return fmt.Errorf("intermediate CA name is required")
	}

	return withTx(s.db, func(tx *sql.Tx) error {
		if err := syncDerivedStatusesTx(tx); err != nil {
			return err
		}

		generation, err := nextGenerationTx(tx, "private_intermediate_cas", rec.Name)
		if err != nil {
			return err
		}
		rec.Generation = generation
		rec.Status = defaultCAStatus(rec.Status)
		if !rec.IsTrusted {
			rec.IsTrusted = true
		}
		if !rec.IsIssuing {
			rec.IsIssuing = true
		}

		if current, err := getActivePrivateIntermediateCAByNameTx(tx, rec.Name); err == nil {
			rec.SupersedesCAID = current.ID
			if _, err := tx.Exec(`
				UPDATE private_intermediate_cas
				SET status = ?, is_issuing = 0, updated_at = ?
				WHERE name = ? AND status = ?
			`, StatusRetired, nowRFC3339(), rec.Name, StatusActive); err != nil {
				return err
			}
		} else if err != sql.ErrNoRows {
			return err
		}

		rec.CreatedAt = defaultCreatedAt(rec.CreatedAt)
		rec.UpdatedAt = time.Now().UTC()

		_, err = tx.Exec(`
			INSERT INTO private_intermediate_cas
			(id, root_ca_id, name, common_name, generation, status, is_trusted, is_issuing, supersedes_ca_id, key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			rec.ID,
			rec.RootCAID,
			rec.Name,
			rec.CommonName,
			rec.Generation,
			rec.Status,
			boolToInt(rec.IsTrusted),
			boolToInt(rec.IsIssuing),
			nullIfEmpty(rec.SupersedesCAID),
			rec.KeyType,
			rec.CertPEM,
			rec.KeyPEM,
			nullIfEmpty(rec.Issuer),
			timeOrEmpty(rec.NotBefore),
			timeOrEmpty(rec.NotAfter),
			timeOrNil(rec.CreatedAt),
			timeOrNil(rec.UpdatedAt),
		)
		return err
	})
}

func (s *Store) GetPrivateIntermediateCAByID(id string) (PrivateIntermediateCA, error) {
	var rec PrivateIntermediateCA
	err := scanPrivateIntermediateCA(s.db.QueryRow(`
		SELECT id, root_ca_id, name, common_name, generation, status, is_trusted, is_issuing, COALESCE(supersedes_ca_id, ''),
		       key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
		FROM private_intermediate_cas
		WHERE id = ?
		LIMIT 1
	`, id), &rec)
	return rec, err
}

func (s *Store) GetIssuingPrivateIntermediateCAByName(name string) (PrivateIntermediateCA, error) {
	var rec PrivateIntermediateCA
	err := scanPrivateIntermediateCA(s.db.QueryRow(`
		SELECT id, root_ca_id, name, common_name, generation, status, is_trusted, is_issuing, COALESCE(supersedes_ca_id, ''),
		       key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
		FROM private_intermediate_cas
		WHERE name = ? AND status = ? AND is_issuing = 1
		ORDER BY generation DESC
		LIMIT 1
	`, name, StatusActive), &rec)
	return rec, err
}

func (s *Store) UpsertPrivateCert(rec PrivateCert) error {
	if rec.ID == "" {
		return fmt.Errorf("private certificate id is required")
	}
	if strings.TrimSpace(rec.CommonName) == "" {
		return fmt.Errorf("private certificate common_name is required")
	}

	return withTx(s.db, func(tx *sql.Tx) error {
		if err := syncDerivedStatusesTx(tx); err != nil {
			return err
		}

		if current, err := getActivePrivateCertByNameTx(tx, rec.CommonName); err == nil {
			rec.SupersedesCertID = current.ID
			if _, err := tx.Exec(`
				UPDATE private_certs
				SET status = ?, updated_at = ?
				WHERE common_name = ? AND status = ?
			`, StatusSuperseded, nowRFC3339(), rec.CommonName, StatusActive); err != nil {
				return err
			}
		} else if err != sql.ErrNoRows {
			return err
		}

		rec.Status = defaultLeafStatus(rec.Status)
		rec.CreatedAt = defaultCreatedAt(rec.CreatedAt)
		rec.UpdatedAt = time.Now().UTC()

		_, err := tx.Exec(`
			INSERT INTO private_certs
			(id, intermediate_ca_id, common_name, sans_csv, cert_type, key_type, cert_pem, key_pem, issuer, status, supersedes_cert_id, revoked_at, not_before, not_after, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			rec.ID,
			rec.IntermediateCAID,
			rec.CommonName,
			nullIfEmpty(rec.SANsCSV),
			rec.CertType,
			rec.KeyType,
			rec.CertPEM,
			rec.KeyPEM,
			nullIfEmpty(rec.Issuer),
			rec.Status,
			nullIfEmpty(rec.SupersedesCertID),
			timeOrEmpty(rec.RevokedAt),
			timeOrEmpty(rec.NotBefore),
			timeOrEmpty(rec.NotAfter),
			timeOrNil(rec.CreatedAt),
			timeOrNil(rec.UpdatedAt),
		)
		return err
	})
}

func (s *Store) ListPrivateCerts(commonName string, includeInactive bool) ([]PrivateCert, error) {
	var (
		rows *sql.Rows
		err  error
	)

	args := []any{}
	var where []string
	if strings.TrimSpace(commonName) != "" {
		where = append(where, "(common_name = ? OR sans_csv LIKE ?)")
		args = append(args, commonName, "%"+commonName+"%")
	}
	if !includeInactive {
		where = append(where, "status = ?")
		args = append(args, StatusActive)
	}

	query := `
		SELECT id, intermediate_ca_id, common_name, COALESCE(sans_csv, ''), cert_type, key_type,
		       cert_pem, key_pem, issuer, status, COALESCE(supersedes_cert_id, ''), revoked_at,
		       not_before, not_after, created_at, updated_at
		FROM private_certs
	`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY common_name, created_at DESC"

	rows, err = s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PrivateCert
	for rows.Next() {
		var rec PrivateCert
		if err := scanPrivateCert(rows, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) GetPublicCertByID(id string) (PublicCert, error) {
	return s.GetByID(id)
}

func (s *Store) GetPrivateCertByID(id string) (PrivateCert, error) {
	var rec PrivateCert
	err := scanPrivateCert(s.db.QueryRow(`
		SELECT id, intermediate_ca_id, common_name, COALESCE(sans_csv, ''), cert_type, key_type,
		       cert_pem, key_pem, issuer, status, COALESCE(supersedes_cert_id, ''), revoked_at,
		       not_before, not_after, created_at, updated_at
		FROM private_certs
		WHERE id = ?
		LIMIT 1
	`, id), &rec)
	return rec, err
}

func (s *Store) GetPrivateCertByName(name string) (PrivateCert, error) {
	var rec PrivateCert
	err := scanPrivateCert(s.db.QueryRow(`
		SELECT id, intermediate_ca_id, common_name, COALESCE(sans_csv, ''), cert_type, key_type,
		       cert_pem, key_pem, issuer, status, COALESCE(supersedes_cert_id, ''), revoked_at,
		       not_before, not_after, created_at, updated_at
		FROM private_certs
		WHERE common_name = ? AND status = ?
		ORDER BY created_at DESC
		LIMIT 1
	`, name, StatusActive), &rec)
	return rec, err
}

func (s *Store) GetPrivateCertByNameOrSAN(name string) (PrivateCert, error) {
	var rec PrivateCert
	err := scanPrivateCert(s.db.QueryRow(`
		SELECT id, intermediate_ca_id, common_name, COALESCE(sans_csv, ''), cert_type, key_type,
		       cert_pem, key_pem, issuer, status, COALESCE(supersedes_cert_id, ''), revoked_at,
		       not_before, not_after, created_at, updated_at
		FROM private_certs
		WHERE status = ?
		  AND (
			common_name = ?
			OR sans_csv = ?
			OR sans_csv LIKE ?
			OR sans_csv LIKE ?
			OR sans_csv LIKE ?
		  )
		ORDER BY created_at DESC
		LIMIT 1
	`,
		StatusActive,
		name,
		name,
		name+",%",
		"%,"+name+",%",
		"%,"+name,
	), &rec)
	return rec, err
}

func (s *Store) ResolveShareTarget(kind, name string) (id string, resolvedName string, err error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	name = strings.TrimSpace(name)

	switch kind {
	case CertKindPublic:
		rec, err := s.GetBySAN(name)
		if err != nil {
			return "", "", err
		}
		return rec.ID, rec.CommonName, nil
	case CertKindPrivate:
		rec, err := s.GetPrivateCertByNameOrSAN(name)
		if err != nil {
			return "", "", err
		}
		return rec.ID, rec.CommonName, nil
	default:
		return "", "", fmt.Errorf("unsupported cert kind: %s", kind)
	}
}

func ensureSchema(db *sql.DB) error {
	if err := ensurePublicCertsSchema(db); err != nil {
		return err
	}
	if err := ensureCertSharesSchema(db); err != nil {
		return err
	}
	if err := ensurePrivateRootCASchema(db); err != nil {
		return err
	}
	if err := ensurePrivateIntermediateCASchema(db); err != nil {
		return err
	}
	if err := ensurePrivateCertsSchema(db); err != nil {
		return err
	}
	return nil
}

func ensurePublicCertsSchema(db *sql.DB) error {
	create := `
		CREATE TABLE IF NOT EXISTS public_certs (
			id TEXT PRIMARY KEY,
			common_name TEXT NOT NULL,
			sans_csv TEXT NOT NULL,
			sans_hash TEXT NOT NULL,
			cert BLOB NOT NULL,
			privkey BLOB NOT NULL,
			provider TEXT,
			email TEXT,
			issuer TEXT,
			status TEXT NOT NULL DEFAULT 'active',
			supersedes_cert_id TEXT,
			revoked_at TEXT,
			not_before TEXT,
			not_after TEXT,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			FOREIGN KEY(supersedes_cert_id) REFERENCES public_certs(id)
		)
	`

	if err := ensureLegacyArchiveTable(db); err != nil {
		return err
	}

	exists, err := tableExists(db, "public_certs")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := db.Exec(create); err != nil {
			return err
		}
		return ensurePublicCertIndexes(db)
	}

	cols, err := tableColumns(db, "public_certs")
	if err != nil {
		return err
	}
	if hasColumns(cols, "status", "supersedes_cert_id", "revoked_at") {
		return ensurePublicCertIndexes(db)
	}

	if err := withTx(db, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`ALTER TABLE public_certs RENAME TO public_certs_old`); err != nil {
			return err
		}
		if _, err := tx.Exec(create); err != nil {
			return err
		}
		_, err := tx.Exec(`
			INSERT INTO public_certs
			(id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, status, supersedes_cert_id, revoked_at, not_before, not_after, created_at, updated_at)
			SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer,
			       ?, NULL, NULL, not_before, not_after, created_at, updated_at
			FROM public_certs_old
		`, StatusActive)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`DROP TABLE public_certs_old`)
		return err
	}); err != nil {
		return err
	}

	return ensurePublicCertIndexes(db)
}

func ensureLegacyArchiveTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS public_certs_archive (
			id TEXT NOT NULL,
			common_name TEXT NOT NULL,
			sans_csv TEXT NOT NULL,
			sans_hash TEXT NOT NULL,
			cert BLOB NOT NULL,
			privkey BLOB NOT NULL,
			provider TEXT,
			email TEXT,
			issuer TEXT,
			not_before TEXT,
			not_after TEXT,
			created_at TEXT,
			updated_at TEXT,
			archived_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
		)
	`)
	return err
}

func ensurePublicCertIndexes(db *sql.DB) error {
	stmts := []string{
		`CREATE INDEX IF NOT EXISTS idx_public_certs_common_name ON public_certs(common_name, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_public_certs_sans_hash ON public_certs(common_name, sans_hash, created_at DESC)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_public_certs_active_common_name ON public_certs(common_name) WHERE status = 'active'`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func ensureCertSharesSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS cert_shares (
			id TEXT PRIMARY KEY,
			cert_kind TEXT NOT NULL,
			cert_id TEXT NOT NULL,
			share_token TEXT NOT NULL UNIQUE,
			mode TEXT NOT NULL,
			share_password_hash TEXT NOT NULL,
			key_password_hash TEXT,
			expires_at TEXT,
			max_views INTEGER,
			view_count INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			last_viewed_at TEXT,
			revoked_at TEXT,
			note TEXT,
			CHECK (cert_kind IN ('public', 'private')),
			CHECK (mode IN ('cert', 'cert_key'))
		)
	`)
	return err
}

func ensurePrivateRootCASchema(db *sql.DB) error {
	create := `
		CREATE TABLE IF NOT EXISTS private_root_cas (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			common_name TEXT NOT NULL,
			generation INTEGER NOT NULL DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'active',
			is_trusted INTEGER NOT NULL DEFAULT 1,
			is_issuing INTEGER NOT NULL DEFAULT 1,
			supersedes_ca_id TEXT,
			key_type TEXT NOT NULL,
			cert_pem BLOB NOT NULL,
			key_pem BLOB NOT NULL,
			issuer TEXT,
			not_before TEXT,
			not_after TEXT,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			FOREIGN KEY(supersedes_ca_id) REFERENCES private_root_cas(id)
		)
	`

	exists, err := tableExists(db, "private_root_cas")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := db.Exec(create); err != nil {
			return err
		}
		return ensurePrivateRootCAIndexes(db)
	}

	cols, err := tableColumns(db, "private_root_cas")
	if err != nil {
		return err
	}
	if hasColumns(cols, "generation", "status", "is_trusted", "is_issuing", "supersedes_ca_id") {
		return ensurePrivateRootCAIndexes(db)
	}

	if err := withTx(db, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`ALTER TABLE private_root_cas RENAME TO private_root_cas_old`); err != nil {
			return err
		}
		if _, err := tx.Exec(create); err != nil {
			return err
		}
		_, err := tx.Exec(`
			INSERT INTO private_root_cas
			(id, name, common_name, generation, status, is_trusted, is_issuing, supersedes_ca_id, key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at)
			SELECT id, name, common_name, 1, ?, 1, 1, NULL, key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
			FROM private_root_cas_old
		`, StatusActive)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`DROP TABLE private_root_cas_old`)
		return err
	}); err != nil {
		return err
	}

	return ensurePrivateRootCAIndexes(db)
}

func ensurePrivateRootCAIndexes(db *sql.DB) error {
	stmts := []string{
		`CREATE INDEX IF NOT EXISTS idx_private_root_cas_name ON private_root_cas(name, generation DESC)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_private_root_cas_active_name ON private_root_cas(name) WHERE status = 'active'`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func ensurePrivateIntermediateCASchema(db *sql.DB) error {
	create := `
		CREATE TABLE IF NOT EXISTS private_intermediate_cas (
			id TEXT PRIMARY KEY,
			root_ca_id TEXT NOT NULL,
			name TEXT NOT NULL,
			common_name TEXT NOT NULL,
			generation INTEGER NOT NULL DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'active',
			is_trusted INTEGER NOT NULL DEFAULT 1,
			is_issuing INTEGER NOT NULL DEFAULT 1,
			supersedes_ca_id TEXT,
			key_type TEXT NOT NULL,
			cert_pem BLOB NOT NULL,
			key_pem BLOB NOT NULL,
			issuer TEXT,
			not_before TEXT,
			not_after TEXT,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			FOREIGN KEY(root_ca_id) REFERENCES private_root_cas(id),
			FOREIGN KEY(supersedes_ca_id) REFERENCES private_intermediate_cas(id)
		)
	`

	exists, err := tableExists(db, "private_intermediate_cas")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := db.Exec(create); err != nil {
			return err
		}
		return ensurePrivateIntermediateCAIndexes(db)
	}

	cols, err := tableColumns(db, "private_intermediate_cas")
	if err != nil {
		return err
	}
	if hasColumns(cols, "generation", "status", "is_trusted", "is_issuing", "supersedes_ca_id") {
		return ensurePrivateIntermediateCAIndexes(db)
	}

	if err := withTx(db, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`ALTER TABLE private_intermediate_cas RENAME TO private_intermediate_cas_old`); err != nil {
			return err
		}
		if _, err := tx.Exec(create); err != nil {
			return err
		}
		_, err := tx.Exec(`
			INSERT INTO private_intermediate_cas
			(id, root_ca_id, name, common_name, generation, status, is_trusted, is_issuing, supersedes_ca_id, key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at)
			SELECT id, root_ca_id, name, common_name, 1, ?, 1, 1, NULL, key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
			FROM private_intermediate_cas_old
		`, StatusActive)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`DROP TABLE private_intermediate_cas_old`)
		return err
	}); err != nil {
		return err
	}

	return ensurePrivateIntermediateCAIndexes(db)
}

func ensurePrivateIntermediateCAIndexes(db *sql.DB) error {
	stmts := []string{
		`CREATE INDEX IF NOT EXISTS idx_private_intermediate_cas_name ON private_intermediate_cas(name, generation DESC)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_private_intermediate_cas_active_name ON private_intermediate_cas(name) WHERE status = 'active'`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func ensurePrivateCertsSchema(db *sql.DB) error {
	create := `
		CREATE TABLE IF NOT EXISTS private_certs (
			id TEXT PRIMARY KEY,
			intermediate_ca_id TEXT NOT NULL,
			common_name TEXT NOT NULL,
			sans_csv TEXT,
			cert_type TEXT NOT NULL,
			key_type TEXT NOT NULL,
			cert_pem BLOB NOT NULL,
			key_pem BLOB NOT NULL,
			issuer TEXT,
			status TEXT NOT NULL DEFAULT 'active',
			supersedes_cert_id TEXT,
			revoked_at TEXT,
			not_before TEXT,
			not_after TEXT,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			FOREIGN KEY(intermediate_ca_id) REFERENCES private_intermediate_cas(id),
			FOREIGN KEY(supersedes_cert_id) REFERENCES private_certs(id)
		)
	`

	exists, err := tableExists(db, "private_certs")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := db.Exec(create); err != nil {
			return err
		}
		return ensurePrivateCertIndexes(db)
	}

	cols, err := tableColumns(db, "private_certs")
	if err != nil {
		return err
	}
	if hasColumns(cols, "status", "supersedes_cert_id", "revoked_at") {
		return ensurePrivateCertIndexes(db)
	}

	if err := withTx(db, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`ALTER TABLE private_certs RENAME TO private_certs_old`); err != nil {
			return err
		}
		if _, err := tx.Exec(create); err != nil {
			return err
		}

		rows, err := tx.Query(`
			SELECT id, intermediate_ca_id, common_name, COALESCE(sans_csv, ''), cert_type, key_type,
			       cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
			FROM private_certs_old
			ORDER BY common_name, created_at, updated_at, id
		`)
		if err != nil {
			return err
		}
		defer rows.Close()

		type legacyPrivateCert struct {
			ID               string
			IntermediateCAID string
			CommonName       string
			SANsCSV          string
			CertType         string
			KeyType          string
			CertPEM          []byte
			KeyPEM           []byte
			Issuer           string
			NotBefore        sql.NullString
			NotAfter         sql.NullString
			CreatedAt        sql.NullString
			UpdatedAt        sql.NullString
		}

		grouped := map[string][]legacyPrivateCert{}
		var names []string
		seenNames := map[string]struct{}{}
		for rows.Next() {
			var rec legacyPrivateCert
			if err := rows.Scan(
				&rec.ID,
				&rec.IntermediateCAID,
				&rec.CommonName,
				&rec.SANsCSV,
				&rec.CertType,
				&rec.KeyType,
				&rec.CertPEM,
				&rec.KeyPEM,
				&rec.Issuer,
				&rec.NotBefore,
				&rec.NotAfter,
				&rec.CreatedAt,
				&rec.UpdatedAt,
			); err != nil {
				return err
			}
			if _, ok := seenNames[rec.CommonName]; !ok {
				seenNames[rec.CommonName] = struct{}{}
				names = append(names, rec.CommonName)
			}
			grouped[rec.CommonName] = append(grouped[rec.CommonName], rec)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		for _, name := range names {
			recs := grouped[name]
			sort.SliceStable(recs, func(i, j int) bool {
				return legacySortKey(recs[i].CreatedAt, recs[i].UpdatedAt, recs[i].ID).Before(
					legacySortKey(recs[j].CreatedAt, recs[j].UpdatedAt, recs[j].ID),
				)
			})

			prevID := ""
			for i, rec := range recs {
				status := StatusSuperseded
				if i == len(recs)-1 {
					status = StatusActive
				}
				if _, err := tx.Exec(`
					INSERT INTO private_certs
					(id, intermediate_ca_id, common_name, sans_csv, cert_type, key_type, cert_pem, key_pem, issuer, status, supersedes_cert_id, revoked_at, not_before, not_after, created_at, updated_at)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)
				`,
					rec.ID,
					rec.IntermediateCAID,
					rec.CommonName,
					nullIfEmpty(rec.SANsCSV),
					rec.CertType,
					rec.KeyType,
					rec.CertPEM,
					rec.KeyPEM,
					nullIfEmpty(rec.Issuer),
					status,
					nullIfEmpty(prevID),
					nullStringValue(rec.NotBefore),
					nullStringValue(rec.NotAfter),
					nullStringValue(rec.CreatedAt),
					nullStringValue(rec.UpdatedAt),
				); err != nil {
					return err
				}
				prevID = rec.ID
			}
		}

		_, err = tx.Exec(`DROP TABLE private_certs_old`)
		return err
	}); err != nil {
		return err
	}

	return ensurePrivateCertIndexes(db)
}

func ensurePrivateCertIndexes(db *sql.DB) error {
	stmts := []string{
		`CREATE INDEX IF NOT EXISTS idx_private_certs_common_name ON private_certs(common_name, created_at DESC)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_private_certs_active_common_name ON private_certs(common_name) WHERE status = 'active'`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func syncDerivedStatuses(db *sql.DB) error {
	return withTx(db, syncDerivedStatusesTx)
}

func syncDerivedStatusesTx(tx *sql.Tx) error {
	now := nowRFC3339()
	stmts := []struct {
		query string
		args  []any
	}{
		{
			query: `UPDATE public_certs SET status = ?, updated_at = ? WHERE status = ? AND not_after IS NOT NULL AND not_after <> '' AND not_after < ?`,
			args:  []any{StatusExpired, now, StatusActive, now},
		},
		{
			query: `UPDATE private_certs SET status = ?, updated_at = ? WHERE status = ? AND not_after IS NOT NULL AND not_after <> '' AND not_after < ?`,
			args:  []any{StatusExpired, now, StatusActive, now},
		},
		{
			query: `UPDATE private_root_cas SET status = ?, is_issuing = 0, updated_at = ? WHERE status = ? AND not_after IS NOT NULL AND not_after <> '' AND not_after < ?`,
			args:  []any{StatusExpired, now, StatusActive, now},
		},
		{
			query: `UPDATE private_intermediate_cas SET status = ?, is_issuing = 0, updated_at = ? WHERE status = ? AND not_after IS NOT NULL AND not_after <> '' AND not_after < ?`,
			args:  []any{StatusExpired, now, StatusActive, now},
		},
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt.query, stmt.args...); err != nil {
			return err
		}
	}
	return nil
}

func scanPublicCert(row scanner, rec *PublicCert) error {
	var revokedAt, notBefore, notAfter, createdAt, updatedAt sql.NullString
	if err := row.Scan(
		&rec.ID,
		&rec.CommonName,
		&rec.SANsCSV,
		&rec.SANsHash,
		&rec.CertPEM,
		&rec.KeyPEM,
		&rec.Provider,
		&rec.Email,
		&rec.Issuer,
		&rec.Status,
		&rec.SupersedesCertID,
		&revokedAt,
		&notBefore,
		&notAfter,
		&createdAt,
		&updatedAt,
	); err != nil {
		return err
	}
	rec.RevokedAt = parseRFC3339Null(revokedAt)
	rec.NotBefore = parseRFC3339Null(notBefore)
	rec.NotAfter = parseRFC3339Null(notAfter)
	rec.CreatedAt = parseRFC3339Null(createdAt)
	rec.UpdatedAt = parseRFC3339Null(updatedAt)
	return nil
}

func scanPrivateRootCA(row scanner, rec *PrivateRootCA) error {
	var isTrusted, isIssuing int
	var notBefore, notAfter, createdAt, updatedAt sql.NullString
	if err := row.Scan(
		&rec.ID,
		&rec.Name,
		&rec.CommonName,
		&rec.Generation,
		&rec.Status,
		&isTrusted,
		&isIssuing,
		&rec.SupersedesCAID,
		&rec.KeyType,
		&rec.CertPEM,
		&rec.KeyPEM,
		&rec.Issuer,
		&notBefore,
		&notAfter,
		&createdAt,
		&updatedAt,
	); err != nil {
		return err
	}
	rec.IsTrusted = isTrusted != 0
	rec.IsIssuing = isIssuing != 0
	rec.NotBefore = parseRFC3339Null(notBefore)
	rec.NotAfter = parseRFC3339Null(notAfter)
	rec.CreatedAt = parseRFC3339Null(createdAt)
	rec.UpdatedAt = parseRFC3339Null(updatedAt)
	return nil
}

func scanPrivateIntermediateCA(row scanner, rec *PrivateIntermediateCA) error {
	var isTrusted, isIssuing int
	var notBefore, notAfter, createdAt, updatedAt sql.NullString
	if err := row.Scan(
		&rec.ID,
		&rec.RootCAID,
		&rec.Name,
		&rec.CommonName,
		&rec.Generation,
		&rec.Status,
		&isTrusted,
		&isIssuing,
		&rec.SupersedesCAID,
		&rec.KeyType,
		&rec.CertPEM,
		&rec.KeyPEM,
		&rec.Issuer,
		&notBefore,
		&notAfter,
		&createdAt,
		&updatedAt,
	); err != nil {
		return err
	}
	rec.IsTrusted = isTrusted != 0
	rec.IsIssuing = isIssuing != 0
	rec.NotBefore = parseRFC3339Null(notBefore)
	rec.NotAfter = parseRFC3339Null(notAfter)
	rec.CreatedAt = parseRFC3339Null(createdAt)
	rec.UpdatedAt = parseRFC3339Null(updatedAt)
	return nil
}

func scanPrivateCert(row scanner, rec *PrivateCert) error {
	var revokedAt, notBefore, notAfter, createdAt, updatedAt sql.NullString
	if err := row.Scan(
		&rec.ID,
		&rec.IntermediateCAID,
		&rec.CommonName,
		&rec.SANsCSV,
		&rec.CertType,
		&rec.KeyType,
		&rec.CertPEM,
		&rec.KeyPEM,
		&rec.Issuer,
		&rec.Status,
		&rec.SupersedesCertID,
		&revokedAt,
		&notBefore,
		&notAfter,
		&createdAt,
		&updatedAt,
	); err != nil {
		return err
	}
	rec.RevokedAt = parseRFC3339Null(revokedAt)
	rec.NotBefore = parseRFC3339Null(notBefore)
	rec.NotAfter = parseRFC3339Null(notAfter)
	rec.CreatedAt = parseRFC3339Null(createdAt)
	rec.UpdatedAt = parseRFC3339Null(updatedAt)
	return nil
}

func getActivePublicCertTx(tx *sql.Tx, commonName string) (PublicCert, error) {
	var rec PublicCert
	err := scanPublicCert(tx.QueryRow(`
		SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, status,
		       COALESCE(supersedes_cert_id, ''), revoked_at, not_before, not_after, created_at, updated_at
		FROM public_certs
		WHERE common_name = ? AND status = ?
		ORDER BY created_at DESC
		LIMIT 1
	`, commonName, StatusActive), &rec)
	return rec, err
}

func getActivePrivateRootCAByNameTx(tx *sql.Tx, name string) (PrivateRootCA, error) {
	var rec PrivateRootCA
	err := scanPrivateRootCA(tx.QueryRow(`
		SELECT id, name, common_name, generation, status, is_trusted, is_issuing, COALESCE(supersedes_ca_id, ''),
		       key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
		FROM private_root_cas
		WHERE name = ? AND status = ?
		ORDER BY generation DESC
		LIMIT 1
	`, name, StatusActive), &rec)
	return rec, err
}

func getActivePrivateIntermediateCAByNameTx(tx *sql.Tx, name string) (PrivateIntermediateCA, error) {
	var rec PrivateIntermediateCA
	err := scanPrivateIntermediateCA(tx.QueryRow(`
		SELECT id, root_ca_id, name, common_name, generation, status, is_trusted, is_issuing, COALESCE(supersedes_ca_id, ''),
		       key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
		FROM private_intermediate_cas
		WHERE name = ? AND status = ?
		ORDER BY generation DESC
		LIMIT 1
	`, name, StatusActive), &rec)
	return rec, err
}

func getActivePrivateCertByNameTx(tx *sql.Tx, name string) (PrivateCert, error) {
	var rec PrivateCert
	err := scanPrivateCert(tx.QueryRow(`
		SELECT id, intermediate_ca_id, common_name, COALESCE(sans_csv, ''), cert_type, key_type,
		       cert_pem, key_pem, issuer, status, COALESCE(supersedes_cert_id, ''), revoked_at,
		       not_before, not_after, created_at, updated_at
		FROM private_certs
		WHERE common_name = ? AND status = ?
		ORDER BY created_at DESC
		LIMIT 1
	`, name, StatusActive), &rec)
	return rec, err
}

func nextGenerationTx(tx *sql.Tx, table, name string) (int, error) {
	query := fmt.Sprintf(`SELECT COALESCE(MAX(generation), 0) FROM %s WHERE name = ?`, table)
	var gen int
	if err := tx.QueryRow(query, name).Scan(&gen); err != nil {
		return 0, err
	}
	return gen + 1, nil
}

func parseRFC3339Null(src sql.NullString) time.Time {
	if !src.Valid || strings.TrimSpace(src.String) == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, src.String); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func timeOrEmpty(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func timeOrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func nullInt64(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}

func nullInt64Value(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}

func nullStringValue(v sql.NullString) any {
	if !v.Valid || strings.TrimSpace(v.String) == "" {
		return nil
	}
	return v.String
}

func defaultCreatedAt(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}

func defaultLeafStatus(status string) string {
	status = strings.TrimSpace(strings.ToLower(status))
	if status == "" {
		return StatusActive
	}
	return status
}

func defaultCAStatus(status string) string {
	status = strings.TrimSpace(strings.ToLower(status))
	if status == "" {
		return StatusActive
	}
	return status
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func legacySortKey(createdAt, updatedAt sql.NullString, id string) time.Time {
	if t := parseRFC3339Null(updatedAt); !t.IsZero() {
		return t
	}
	if t := parseRFC3339Null(createdAt); !t.IsZero() {
		return t
	}
	return time.Unix(0, 0).UTC()
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func tableExists(db *sql.DB, name string) (bool, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&count)
	return count > 0, err
}

func tableColumns(db *sql.DB, name string) (map[string]struct{}, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, name))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := map[string]struct{}{}
	for rows.Next() {
		var (
			cid        int
			columnName string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &columnName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return nil, err
		}
		cols[columnName] = struct{}{}
	}
	return cols, rows.Err()
}

func hasColumns(cols map[string]struct{}, required ...string) bool {
	for _, col := range required {
		if _, ok := cols[col]; !ok {
			return false
		}
	}
	return true
}

func withTx(db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if err = fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
