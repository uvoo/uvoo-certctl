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

const (
    CertKindPublic  = "public"
    CertKindPrivate = "private"
)

type Store struct{ db *sql.DB }

type PublicCert struct {
    ID         string
    CommonName string
    SANsCSV    string
    SANsHash   string

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
    ID         string
    Name       string
    CommonName string
    KeyType    string
    CertPEM    []byte
    KeyPEM     []byte
    Issuer     string
    NotBefore  time.Time
    NotAfter   time.Time
    CreatedAt  time.Time
    UpdatedAt  time.Time
}

type PrivateIntermediateCA struct {
    ID         string
    RootCAID   string
    Name       string
    CommonName string
    KeyType    string
    CertPEM    []byte
    KeyPEM     []byte
    Issuer     string
    NotBefore  time.Time
    NotAfter   time.Time
    CreatedAt  time.Time
    UpdatedAt  time.Time
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
    NotBefore        time.Time
    NotAfter         time.Time
    CreatedAt        time.Time
    UpdatedAt        time.Time
}

func Open(path string) (*Store, error) {
    dir := filepath.Dir(path)
    if dir != "." {
        if err := os.MkdirAll(dir, 0o755); err != nil {
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
        `CREATE TABLE IF NOT EXISTS public_certs (
                        id TEXT PRIMARY KEY,
                        common_name TEXT NOT NULL UNIQUE,
                        sans_csv TEXT NOT NULL,
                        sans_hash TEXT NOT NULL,
                        cert BLOB NOT NULL,
                        privkey BLOB NOT NULL,
                        provider TEXT,
                        email TEXT,
                        issuer TEXT,
                        not_before TEXT,
                        not_after TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )`,

        `CREATE TABLE IF NOT EXISTS public_certs_archive (
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
                        archived_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )`,

    `CREATE TABLE IF NOT EXISTS cert_shares (
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
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_viewed_at TEXT,
        revoked_at TEXT,
        note TEXT,
        CHECK (cert_kind IN ('public', 'private')),
        CHECK (mode IN ('cert', 'cert_key'))
    )`,

    `CREATE TABLE IF NOT EXISTS private_root_cas (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    common_name TEXT NOT NULL,
    key_type TEXT NOT NULL,
    cert_pem BLOB NOT NULL,
    key_pem BLOB NOT NULL,
    issuer TEXT,
    not_before TEXT,
    not_after TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`,

        `CREATE TABLE IF NOT EXISTS private_intermediate_cas (
    id TEXT PRIMARY KEY,
    root_ca_id TEXT NOT NULL,
    name TEXT NOT NULL UNIQUE,
    common_name TEXT NOT NULL,
    key_type TEXT NOT NULL,
    cert_pem BLOB NOT NULL,
    key_pem BLOB NOT NULL,
    issuer TEXT,
    not_before TEXT,
    not_after TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(root_ca_id) REFERENCES private_root_cas(id)
)`,

        `CREATE TABLE IF NOT EXISTS private_certs (
    id TEXT PRIMARY KEY,
    intermediate_ca_id TEXT NOT NULL,
    common_name TEXT NOT NULL,
    sans_csv TEXT,
    cert_type TEXT NOT NULL,
    key_type TEXT NOT NULL,
    cert_pem BLOB NOT NULL,
    key_pem BLOB NOT NULL,
    issuer TEXT,
    not_before TEXT,
    not_after TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(intermediate_ca_id) REFERENCES private_intermediate_cas(id)
)`,
    }

    for _, stmt := range stmts {
        if _, err := db.Exec(stmt); err != nil {
            db.Close()
            return nil, err
        }
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

func NormalizeSANs(sans []string) ([]string, string, string) {
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

    csv := strings.Join(out, ",")
    sum := sha256.Sum256([]byte(csv))
    hash := hex.EncodeToString(sum[:])

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

    _, _ = s.db.Exec(`
                INSERT INTO public_certs_archive
                (id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at)
                SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
                FROM public_certs
                WHERE common_name = ?
        `, rec.CommonName)

    _, err := s.db.Exec(`
                INSERT INTO public_certs
                (id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP)
                ON CONFLICT(common_name) DO UPDATE SET
                        id=excluded.id,
                        sans_csv=excluded.sans_csv,
                        sans_hash=excluded.sans_hash,
                        cert=excluded.cert,
                        privkey=excluded.privkey,
                        provider=excluded.provider,
                        email=excluded.email,
                        issuer=excluded.issuer,
                        not_before=excluded.not_before,
                        not_after=excluded.not_after,
                        updated_at=CURRENT_TIMESTAMP
        `,
        rec.ID,
        rec.CommonName,
        rec.SANsCSV,
        rec.SANsHash,
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

func (s *Store) Get(commonName string) (PublicCert, error) {
    var rec PublicCert
    var nb, na, ca, ua sql.NullString

    err := s.db.QueryRow(`
                SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
                FROM public_certs
                WHERE common_name = ?
                ORDER BY updated_at DESC
                LIMIT 1
        `, commonName).Scan(
        &rec.ID,
        &rec.CommonName,
        &rec.SANsCSV,
        &rec.SANsHash,
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

func (s *Store) List(name string) ([]PublicCert, error) {
    var (
        rows *sql.Rows
        err  error
    )

    if name != "" {
        rows, err = s.db.Query(`
                        SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
                        FROM public_certs
                        WHERE common_name = ? OR sans_csv LIKE ?
                        ORDER BY common_name, updated_at DESC
                `, name, "%"+name+"%")
    } else {
        rows, err = s.db.Query(`
                        SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
                        FROM public_certs
                        ORDER BY common_name, updated_at DESC
                `)
    }
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []PublicCert
    for rows.Next() {
        var rec PublicCert
        var nb, na, ca, ua sql.NullString

        if err := rows.Scan(
            &rec.ID,
            &rec.CommonName,
            &rec.SANsCSV,
            &rec.SANsHash,
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

func (s *Store) GetByCommonName(name string) (PublicCert, error) {
    return s.Get(name)
}

func (s *Store) GetBySAN(name string) (PublicCert, error) {
    var rec PublicCert
    var nb, na, ca, ua sql.NullString

    err := s.db.QueryRow(`
                SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
                FROM public_certs
                WHERE common_name = ?
                   OR sans_csv = ?
                   OR sans_csv LIKE ?
                   OR sans_csv LIKE ?
                   OR sans_csv LIKE ?
                ORDER BY updated_at DESC
                LIMIT 1
        `,
        name,
        name,
        name+",%",
        "%,"+name+",%",
        "%,"+name,
    ).Scan(
        &rec.ID,
        &rec.CommonName,
        &rec.SANsCSV,
        &rec.SANsHash,
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

func (s *Store) FindByHash(commonName, hash string) (PublicCert, error) {
    var rec PublicCert
    var nb, na, ca, ua sql.NullString

    err := s.db.QueryRow(`
                SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
                FROM public_certs
                WHERE common_name = ? AND sans_hash = ?
                LIMIT 1
        `, commonName, hash).Scan(
        &rec.ID,
        &rec.CommonName,
        &rec.SANsCSV,
        &rec.SANsHash,
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

func nullInt64Value(v sql.NullInt64) interface{} {
	if !v.Valid {
		return nil
	}
	return v.Int64
}

func (s *Store) GetByID(id string) (PublicCert, error) {
    var rec PublicCert
    var nb, na, ca, ua sql.NullString

    err := s.db.QueryRow(`
        SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
        FROM public_certs
        WHERE id = ?
        LIMIT 1
    `, id).Scan(
        &rec.ID,
        &rec.CommonName,
        &rec.SANsCSV,
        &rec.SANsHash,
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
		if _, err := s.GetPublicCertByID(sh.CertID); err != nil {
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

func (s *Store) IncrementShareView(id string) error {
    _, err := s.db.Exec(`
                UPDATE cert_shares
                SET view_count = view_count + 1,
                    last_viewed_at = CURRENT_TIMESTAMP
                WHERE id = ?
        `, id)
    return err
}

func (s *Store) RevokeShare(id string) error {
    _, err := s.db.Exec(`
                UPDATE cert_shares
                SET revoked_at = CURRENT_TIMESTAMP
                WHERE id = ?
        `, id)
    return err
}

func (s *Store) UpsertPrivateRootCA(rec PrivateRootCA) error {
    _, err := s.db.Exec(`
                INSERT INTO private_root_cas
                (id, name, common_name, key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP)
                ON CONFLICT(name) DO UPDATE SET
                        id=excluded.id,
                        common_name=excluded.common_name,
                        key_type=excluded.key_type,
                        cert_pem=excluded.cert_pem,
                        key_pem=excluded.key_pem,
                        issuer=excluded.issuer,
                        not_before=excluded.not_before,
                        not_after=excluded.not_after,
                        updated_at=CURRENT_TIMESTAMP
        `,
        rec.ID,
        rec.Name,
        rec.CommonName,
        rec.KeyType,
        rec.CertPEM,
        rec.KeyPEM,
        rec.Issuer,
        timeOrEmpty(rec.NotBefore),
        timeOrEmpty(rec.NotAfter),
        timeOrNil(rec.CreatedAt),
    )
    return err
}

func (s *Store) GetPrivateRootCAByID(id string) (PrivateRootCA, error) {
    var rec PrivateRootCA
    var nb, na, ca, ua sql.NullString

    err := s.db.QueryRow(`
                SELECT id, name, common_name, key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
                FROM private_root_cas
                WHERE id = ?
                LIMIT 1
        `, id).Scan(
        &rec.ID,
        &rec.Name,
        &rec.CommonName,
        &rec.KeyType,
        &rec.CertPEM,
        &rec.KeyPEM,
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

func (s *Store) UpsertPrivateIntermediateCA(rec PrivateIntermediateCA) error {
    _, err := s.db.Exec(`
                INSERT INTO private_intermediate_cas
                (id, root_ca_id, name, common_name, key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP)
                ON CONFLICT(name) DO UPDATE SET
                        id=excluded.id,
                        root_ca_id=excluded.root_ca_id,
                        common_name=excluded.common_name,
                        key_type=excluded.key_type,
                        cert_pem=excluded.cert_pem,
                        key_pem=excluded.key_pem,
                        issuer=excluded.issuer,
                        not_before=excluded.not_before,
                        not_after=excluded.not_after,
                        updated_at=CURRENT_TIMESTAMP
        `,
        rec.ID,
        rec.RootCAID,
        rec.Name,
        rec.CommonName,
        rec.KeyType,
        rec.CertPEM,
        rec.KeyPEM,
        rec.Issuer,
        timeOrEmpty(rec.NotBefore),
        timeOrEmpty(rec.NotAfter),
        timeOrNil(rec.CreatedAt),
    )
    return err
}

func (s *Store) GetPrivateIntermediateCAByID(id string) (PrivateIntermediateCA, error) {
    var rec PrivateIntermediateCA
    var nb, na, ca, ua sql.NullString

    err := s.db.QueryRow(`
                SELECT id, root_ca_id, name, common_name, key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
                FROM private_intermediate_cas
                WHERE id = ?
                LIMIT 1
        `, id).Scan(
        &rec.ID,
        &rec.RootCAID,
        &rec.Name,
        &rec.CommonName,
        &rec.KeyType,
        &rec.CertPEM,
        &rec.KeyPEM,
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

func (s *Store) UpsertPrivateCert(rec PrivateCert) error {
    _, err := s.db.Exec(`
                INSERT INTO private_certs
                (id, intermediate_ca_id, common_name, sans_csv, cert_type, key_type, cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP)
        `,
        rec.ID,
        rec.IntermediateCAID,
        rec.CommonName,
        rec.SANsCSV,
        rec.CertType,
        rec.KeyType,
        rec.CertPEM,
        rec.KeyPEM,
        rec.Issuer,
        timeOrEmpty(rec.NotBefore),
        timeOrEmpty(rec.NotAfter),
        timeOrNil(rec.CreatedAt),
    )
    return err
}

func (s *Store) ListPrivateCerts(commonName string) ([]PrivateCert, error) {
    var (
        rows *sql.Rows
        err  error
    )

    if commonName != "" {
        rows, err = s.db.Query(`
                        SELECT id, intermediate_ca_id, common_name, COALESCE(sans_csv, ''), cert_type, key_type,
                               cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
                        FROM private_certs
                        WHERE common_name = ? OR sans_csv LIKE ?
                        ORDER BY common_name, updated_at DESC
                `, commonName, "%"+commonName+"%")
    } else {
        rows, err = s.db.Query(`
                        SELECT id, intermediate_ca_id, common_name, COALESCE(sans_csv, ''), cert_type, key_type,
                               cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
                        FROM private_certs
                        ORDER BY common_name, updated_at DESC
                `)
    }
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []PrivateCert
    for rows.Next() {
        var rec PrivateCert
        var nb, na, ca, ua sql.NullString

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


func (s *Store) GetPublicCertByID(id string) (PublicCert, error) {
	var rec PublicCert
	var nb, na, ca, ua sql.NullString

	err := s.db.QueryRow(`
		SELECT id, common_name, sans_csv, sans_hash, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
		FROM public_certs
		WHERE id = ?
		LIMIT 1
	`, id).Scan(
		&rec.ID,
		&rec.CommonName,
		&rec.SANsCSV,
		&rec.SANsHash,
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

func (s *Store) GetPrivateCertByID(id string) (PrivateCert, error) {
	var rec PrivateCert
	var nb, na, ca, ua sql.NullString

	err := s.db.QueryRow(`
		SELECT id, intermediate_ca_id, common_name, COALESCE(sans_csv, ''), cert_type, key_type,
		       cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
		FROM private_certs
		WHERE id = ?
		LIMIT 1
	`, id).Scan(
		&rec.ID,
		&rec.IntermediateCAID,
		&rec.CommonName,
		&rec.SANsCSV,
		&rec.CertType,
		&rec.KeyType,
		&rec.CertPEM,
		&rec.KeyPEM,
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

func (s *Store) GetPrivateCertByName(name string) (PrivateCert, error) {
	var rec PrivateCert
	var nb, na, ca, ua sql.NullString

	err := s.db.QueryRow(`
		SELECT id, intermediate_ca_id, common_name, COALESCE(sans_csv, ''), cert_type, key_type,
		       cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
		FROM private_certs
		WHERE common_name = ?
		ORDER BY updated_at DESC
		LIMIT 1
	`, name).Scan(
		&rec.ID,
		&rec.IntermediateCAID,
		&rec.CommonName,
		&rec.SANsCSV,
		&rec.CertType,
		&rec.KeyType,
		&rec.CertPEM,
		&rec.KeyPEM,
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

func (s *Store) GetPrivateCertByNameOrSAN(name string) (PrivateCert, error) {
	var rec PrivateCert
	var nb, na, ca, ua sql.NullString

	err := s.db.QueryRow(`
		SELECT id, intermediate_ca_id, common_name, COALESCE(sans_csv, ''), cert_type, key_type,
		       cert_pem, key_pem, issuer, not_before, not_after, created_at, updated_at
		FROM private_certs
		WHERE common_name = ?
		   OR sans_csv = ?
		   OR sans_csv LIKE ?
		   OR sans_csv LIKE ?
		   OR sans_csv LIKE ?
		ORDER BY updated_at DESC
		LIMIT 1
	`,
		name,
		name,
		name+",%",
		"%,"+name+",%",
		"%,"+name,
	).Scan(
		&rec.ID,
		&rec.IntermediateCAID,
		&rec.CommonName,
		&rec.SANsCSV,
		&rec.CertType,
		&rec.KeyType,
		&rec.CertPEM,
		&rec.KeyPEM,
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
