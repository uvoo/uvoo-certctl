package storage

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
 	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct{ db *sql.DB }

type Record struct {
	Domain    string
	CertPEM   []byte
	KeyPEM    []byte
	Provider  string
	Email     string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
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
			domain TEXT PRIMARY KEY,
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
		`ALTER TABLE certs ADD COLUMN provider TEXT`,
		`ALTER TABLE certs ADD COLUMN email TEXT`,
		`ALTER TABLE certs ADD COLUMN issuer TEXT`,
		`ALTER TABLE certs ADD COLUMN not_before TEXT`,
		`ALTER TABLE certs ADD COLUMN not_after TEXT`,
		`ALTER TABLE certs ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP`,
		`ALTER TABLE certs ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP`,
	}
	for i, stmt := range stmts {
		if i == 0 {
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

func (s *Store) Upsert(rec Record) error {
	_, err := s.db.Exec(`INSERT INTO certs
		(domain, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP)
		ON CONFLICT(domain) DO UPDATE SET
			cert=excluded.cert,
			privkey=excluded.privkey,
			provider=excluded.provider,
			email=excluded.email,
			issuer=excluded.issuer,
			not_before=excluded.not_before,
			not_after=excluded.not_after,
			updated_at=CURRENT_TIMESTAMP`,
		rec.Domain,
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

func (s *Store) Get(domain string) (Record, error) {
	var rec Record
	var nb, na, ca, ua sql.NullString
	err := s.db.QueryRow(`SELECT domain, cert, privkey, provider, email, issuer, not_before, not_after, created_at, updated_at
		FROM certs WHERE domain = ?`, domain).Scan(
		&rec.Domain, &rec.CertPEM, &rec.KeyPEM, &rec.Provider, &rec.Email, &rec.Issuer, &nb, &na, &ca, &ua,
	)
	if err != nil {
		return rec, err
	}
	parse := func(src sql.NullString) time.Time {
		if !src.Valid || src.String == "" {
			return time.Time{}
		}
		t, _ := time.Parse(time.RFC3339, src.String)
		return t
	}
	rec.NotBefore = parse(nb)
	rec.NotAfter = parse(na)
	rec.CreatedAt = parse(ca)
	rec.UpdatedAt = parse(ua)
	return rec, nil
}
