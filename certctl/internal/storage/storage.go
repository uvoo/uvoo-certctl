package storage

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct{ db *sql.DB }

type Record struct {
	ID          string
	Domain      string // primary domain
	DomainsCSV  string
	DomainsHash string

	CertPEM  []byte
	KeyPEM   []byte
	Provider string
	Email    string
	Issuer   string

	NotBefore time.Time
	NotAfter  time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

type CertShare struct {
	ID                string
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

func Open(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		db.Close()
		return nil, err
	}

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS certs (
			id TEXT PRIMARY KEY,
			domain TEXT NOT NULL,
			domains_csv TEXT NOT NULL,
			domains_hash TEXT NOT NULL,
			cert BLOB NOT NULL,
			privkey BLOB NOT NULL,
			provider TEXT,
			email TEXT,
			issuer TEXT,
			not_before TEXT,
			not_after TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(domain, domains_hash)
		)`,

		`CREATE TABLE IF NOT EXISTS certs_archive (
			id TEXT NOT NULL,
			domain TEXT NOT NULL,
			domains_csv TEXT NOT NULL,
			domains_hash TEXT NOT NULL,
			cert BLOB NOT NULL,
			privkey BLOB NOT NULL,
			provider TEXT,
			email TEXT,
			issuer TEXT,
			not_before TEXT,
			not_after TEXT,
			created_at TEXT,
			updated_at TEXT,
			archived_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS cert_shares (
    id TEXT PRIMARY KEY,
    cert_id TEXT NOT NULL,
    share_token TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL,
    share_password_hash TEXT NOT NULL,
    key_password_hash TEXT,
    expires_at TEXT,
    max_views INTEGER,
    view_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_viewed_at TEXT,
    revoked_at TEXT,
    note TEXT,
    FOREIGN KEY(cert_id) REFERENCES certs(id)
)`,

		// Best-effort migrations for older DBs.
		`ALTER TABLE certs ADD COLUMN id TEXT`,
		`ALTER TABLE certs ADD COLUMN domains_csv TEXT`,
		`ALTER TABLE certs ADD COLUMN domains_hash TEXT`,
		`ALTER TABLE certs ADD COLUMN provider TEXT`,
		`ALTER TABLE certs ADD COLUMN email TEXT`,
		`ALTER TABLE certs ADD COLUMN issuer TEXT`,
		`ALTER TABLE certs ADD COLUMN not_before TEXT`,
		`ALTER TABLE certs ADD COLUMN not_after TEXT`,
		`ALTER TABLE certs ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP`,
		`ALTER TABLE certs ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP`,
	}

	for i, stmt := range stmts {
		if i < 2 {
			if _, err := db.Exec(stmt); err != nil {
				db.Close()
				return nil, err
			}
			continue
		}
		_, _ = db.Exec(stmt)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ParseCertMetadata(certPEM []byte) (issuer string, notBefore, notAfter time.Time, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", time.Time{}, time.Time{}, fmt.Errorf("invalid PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	return nameToString(cert.Issuer), cert.NotBefore.UTC(), cert.NotAfter.UTC(), nil
}

func nameToString(n pkix.Name) string {
	if n.CommonName != "" {
		return n.CommonName
	}
	return n.String()
}

func NormalizeDomains(domains []string) ([]string, string, string) {
	set := map[string]struct{}{}

	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		set[d] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)

	csv := strings.Join(out, ",")
	sum := sha256.Sum256([]byte(csv))
	hash := hex.EncodeToString(sum[:])

	return out, csv, hash
}

func (s *Store) Upsert(rec Record) error {
	if rec.Domain == "" {
		return fmt.Errorf("record domain is required")
	}
	if rec.DomainsCSV == "" || rec.DomainsHash == "" {
		return fmt.Errorf("record domains_csv and domains_hash are required")
	}
	if rec.ID == "" {
		return fmt.Errorf("record id is required")
	}

	// Archive current active row before replacing it.
	_, _ = s.db.Exec(`
		INSERT INTO certs_archive
		(id, domain, domains_csv, domains_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at)
		SELECT id, domain, domains_csv, domains_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
		FROM certs
		WHERE domain = ? AND domains_hash = ?
	`, rec.Domain, rec.DomainsHash)

	_, err := s.db.Exec(`
		INSERT INTO certs
		(id, domain, domains_csv, domains_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP)
		ON CONFLICT(domain, domains_hash) DO UPDATE SET
			id=excluded.id,
			cert=excluded.cert,
			privkey=excluded.privkey,
			provider=excluded.provider,
			email=excluded.email,
			issuer=excluded.issuer,
			not_before=excluded.not_before,
			not_after=excluded.not_after,
			domains_csv=excluded.domains_csv,
			updated_at=CURRENT_TIMESTAMP
	`,
		rec.ID,
		rec.Domain,
		rec.DomainsCSV,
		rec.DomainsHash,
		rec.CertPEM,
		rec.KeyPEM,
		rec.Provider,
		rec.Email,
		rec.Issuer,
		timeOrEmpty(rec.NotBefore),
		timeOrEmpty(rec.NotAfter),
		timeOrNil(rec.CreatedAt),
	)
	return err
}

func (s *Store) Get(domain string) (Record, error) {
	var rec Record
	var nb, na, ca, ua sql.NullString

	err := s.db.QueryRow(`
		SELECT id, domain, domains_csv, domains_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
		FROM certs
		WHERE domain = ?
		ORDER BY updated_at DESC
		LIMIT 1
	`, domain).Scan(
		&rec.ID,
		&rec.Domain,
		&rec.DomainsCSV,
		&rec.DomainsHash,
		&rec.CertPEM,
		&rec.KeyPEM,
		&rec.Provider,
		&rec.Email,
		&rec.Issuer,
		&nb,
		&na,
		&ca,
		&ua,
	)
	if err != nil {
		return rec, err
	}

	rec.NotBefore = parseRFC3339Null(nb)
	rec.NotAfter = parseRFC3339Null(na)
	rec.CreatedAt = parseRFC3339Null(ca)
	rec.UpdatedAt = parseRFC3339Null(ua)

	return rec, nil
}

func (s *Store) List(domain string) ([]Record, error) {
	var (
		rows *sql.Rows
		err  error
	)

	if domain != "" {
		rows, err = s.db.Query(`
			SELECT id, domain, domains_csv, domains_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
			FROM certs
			WHERE domain = ? OR domains_csv LIKE ?
			ORDER BY domain, updated_at DESC
		`, domain, "%"+domain+"%")
	} else {
		rows, err = s.db.Query(`
			SELECT id, domain, domains_csv, domains_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
			FROM certs
			ORDER BY domain, updated_at DESC
		`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		var rec Record
		var nb, na, ca, ua sql.NullString

		if err := rows.Scan(
			&rec.ID,
			&rec.Domain,
			&rec.DomainsCSV,
			&rec.DomainsHash,
			&rec.CertPEM,
			&rec.KeyPEM,
			&rec.Provider,
			&rec.Email,
			&rec.Issuer,
			&nb,
			&na,
			&ca,
			&ua,
		); err != nil {
			return nil, err
		}

		rec.NotBefore = parseRFC3339Null(nb)
		rec.NotAfter = parseRFC3339Null(na)
		rec.CreatedAt = parseRFC3339Null(ca)
		rec.UpdatedAt = parseRFC3339Null(ua)

		out = append(out, rec)
	}

	return out, rows.Err()
}

func parseRFC3339Null(src sql.NullString) time.Time {
	if !src.Valid || src.String == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, src.String)
	return t
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

func PickPrimary(domains []string) string {
	// Prefer non-wildcard root domain
	for _, d := range domains {
		if !strings.HasPrefix(d, "*.") {
			return d
		}
	}
	// fallback
	if len(domains) > 0 {
		return domains[0]
	}
	return ""
}

func (s *Store) GetByDomain(domain string) (Record, error) {
	var rec Record
	var nb, na, ca, ua sql.NullString

	err := s.db.QueryRow(`
		SELECT id, domain, domains_csv, domains_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
		FROM certs
		WHERE domain = ?
		   OR domains_csv = ?
		   OR domains_csv LIKE ?
		   OR domains_csv LIKE ?
		   OR domains_csv LIKE ?
		ORDER BY updated_at DESC
		LIMIT 1
	`,
		domain,
		domain,
		domain+",%",
		"%,"+domain+",%",
		"%,"+domain,
	).Scan(
		&rec.ID,
		&rec.Domain,
		&rec.DomainsCSV,
		&rec.DomainsHash,
		&rec.CertPEM,
		&rec.KeyPEM,
		&rec.Provider,
		&rec.Email,
		&rec.Issuer,
		&nb,
		&na,
		&ca,
		&ua,
	)
	if err != nil {
		return rec, err
	}

	rec.NotBefore = parseRFC3339Null(nb)
	rec.NotAfter = parseRFC3339Null(na)
	rec.CreatedAt = parseRFC3339Null(ca)
	rec.UpdatedAt = parseRFC3339Null(ua)

	return rec, nil
}

func (s *Store) FindByHash(domain, hash string) (Record, error) {
	var rec Record
	var nb, na, ca, ua sql.NullString

	err := s.db.QueryRow(`
		SELECT id, domain, domains_csv, domains_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
		FROM certs
		WHERE domain = ? AND domains_hash = ?
		LIMIT 1
	`, domain, hash).Scan(
		&rec.ID,
		&rec.Domain,
		&rec.DomainsCSV,
		&rec.DomainsHash,
		&rec.CertPEM,
		&rec.KeyPEM,
		&rec.Provider,
		&rec.Email,
		&rec.Issuer,
		&nb,
		&na,
		&ca,
		&ua,
	)
	if err != nil {
		return rec, err
	}

	rec.NotBefore = parseRFC3339Null(nb)
	rec.NotAfter = parseRFC3339Null(na)
	rec.CreatedAt = parseRFC3339Null(ca)
	rec.UpdatedAt = parseRFC3339Null(ua)

	return rec, nil
}

func (s *Store) CreateShare(sh CertShare) error {
	_, err := s.db.Exec(`
		INSERT INTO cert_shares
		(id, cert_id, share_token, mode, share_password_hash, key_password_hash, expires_at, max_views, view_count, created_at, note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP, ?)
	`,
		sh.ID,
		sh.CertID,
		sh.ShareToken,
		sh.Mode,
		sh.SharePasswordHash,
		nullIfEmpty(sh.KeyPasswordHash),
		timeOrEmpty(sh.ExpiresAt),
		nullInt64(sh.MaxViews),
		sh.Note,
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
			SELECT id, cert_id, share_token, mode, share_password_hash, COALESCE(key_password_hash, ''),
			       expires_at, max_views, view_count, created_at, last_viewed_at, revoked_at, COALESCE(note, '')
			FROM cert_shares
			WHERE cert_id = ?
			ORDER BY created_at DESC
		`, certID)
	} else {
		rows, err = s.db.Query(`
			SELECT id, cert_id, share_token, mode, share_password_hash, COALESCE(key_password_hash, ''),
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
		SELECT id, cert_id, share_token, mode, share_password_hash, COALESCE(key_password_hash, ''),
		       expires_at, max_views, view_count, created_at, last_viewed_at, revoked_at, COALESCE(note, '')
		FROM cert_shares
		WHERE share_token = ?
		LIMIT 1
	`, token).Scan(
		&sh.ID,
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

func (s *Store) RevokeShare(id string) error {
	_, err := s.db.Exec(`
		UPDATE cert_shares
		SET revoked_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, id)
	return err
}

func (s *Store) IncrementShareView(id string) error {
	_, err := s.db.Exec(`
		UPDATE cert_shares
		SET view_count = view_count + 1,
		    last_viewed_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, id)
	return err
}

func (s *Store) GetByID(id string) (Record, error) {
	var rec Record
	var nb, na, ca, ua sql.NullString

	err := s.db.QueryRow(`
		SELECT id, domain, domains_csv, domains_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
		FROM certs
		WHERE id = ?
		LIMIT 1
	`, id).Scan(
		&rec.ID,
		&rec.Domain,
		&rec.DomainsCSV,
		&rec.DomainsHash,
		&rec.CertPEM,
		&rec.KeyPEM,
		&rec.Provider,
		&rec.Email,
		&rec.Issuer,
		&nb,
		&na,
		&ca,
		&ua,
	)
	if err != nil {
		return rec, err
	}

	rec.NotBefore = parseRFC3339Null(nb)
	rec.NotAfter = parseRFC3339Null(na)
	rec.CreatedAt = parseRFC3339Null(ca)
	rec.UpdatedAt = parseRFC3339Null(ua)

	return rec, nil
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
