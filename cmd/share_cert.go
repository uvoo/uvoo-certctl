package cmd

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"uvoocertctl/internal/storage"
	"uvoocertctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var kind string
	var name string
	var mode string
	var sharePassword string
	var keyPassword string
	var expiresInRaw string
	var maxViews int64
	var note string
	var baseURL string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "share-cert",
		Short: "Create a share URL for a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			kind = strings.ToLower(strings.TrimSpace(kind))
			name = strings.TrimSpace(name)
			mode = strings.ToLower(strings.TrimSpace(mode))

			if kind != storage.CertKindPublic && kind != storage.CertKindPrivate {
				return fmt.Errorf("--kind must be %q or %q", storage.CertKindPublic, storage.CertKindPrivate)
			}
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			if mode != "cert" && mode != "cert_key" {
				return fmt.Errorf("--mode must be cert or cert_key")
			}
			if kind == storage.CertKindPublic && mode == "cert_key" {
				return fmt.Errorf("--mode=cert_key is only valid for private certificates")
			}
			sharePassword, err := util.ResolveSecretValue(sharePassword, "CERTCTL_SHARE_PASSWORD")
			if err != nil {
				return err
			}
			if sharePassword == "" {
				return fmt.Errorf("--share-password is required")
			}
			keyPassword, err = util.ResolveSecretValue(keyPassword, "CERTCTL_SHARE_KEY_PASSWORD")
			if err != nil {
				return err
			}
			if mode == "cert_key" && keyPassword == "" {
				return fmt.Errorf("--key-password is required when --mode=cert_key")
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			targetID, resolvedName, err := store.ResolveShareTarget(kind, name)
			if err != nil {
				return fmt.Errorf("certificate not found for %s %q: %w", kind, name, err)
			}
			if kind == storage.CertKindPrivate && mode == "cert_key" {
				rec, err := store.GetPrivateCertByID(targetID)
				if err != nil {
					return err
				}
				if !privateKeyStored(rec.KeyPEM) {
					return fmt.Errorf("private key is not stored for csr-based private certificate %s", rec.CommonName)
				}
			}

			shareHash, err := util.HashPassword(sharePassword)
			if err != nil {
				return err
			}

			var keyHash string
			if keyPassword != "" {
				keyHash, err = util.HashPassword(keyPassword)
				if err != nil {
					return err
				}
			}

			token, err := util.NewShareToken()
			if err != nil {
				return err
			}

			expiresIn, err := util.ParseFlexibleDuration(expiresInRaw)
			if err != nil {
				return fmt.Errorf("invalid --expires-in: %w", err)
			}

			sh := storage.CertShare{
				ID:                util.NewID(),
				CertKind:          kind,
				CertID:            targetID,
				ShareToken:        token,
				Mode:              mode,
				SharePasswordHash: shareHash,
				KeyPasswordHash:   keyHash,
				ExpiresAt:         time.Now().UTC().Add(expiresIn),
				Note:              note,
			}
			if maxViews > 0 {
				sh.MaxViews = sql.NullInt64{Int64: maxViews, Valid: true}
			}

			if err := store.CreateShare(sh); err != nil {
				return err
			}
			logAuditEvent(store, "share_cert", "share", sh.ID, resolvedName)
			if jsonOut {
				payload := map[string]any{
					"share_id":    sh.ID,
					"cert_kind":   sh.CertKind,
					"cert_id":     sh.CertID,
					"name":        resolvedName,
					"mode":        sh.Mode,
					"expires_at":  formatTimeValue(sh.ExpiresAt),
					"max_views":   nullableInt64Value(sh.MaxViews),
					"share_token": sh.ShareToken,
				}
				if baseURL != "" {
					payload["url"] = strings.TrimRight(baseURL, "/") + "/share/" + sh.ShareToken
				}
				return printJSON(payload)
			}

			fmt.Println("Share created")
			fmt.Printf("share id:   %s\n", sh.ID)
			fmt.Printf("cert kind:  %s\n", sh.CertKind)
			fmt.Printf("cert id:    %s\n", sh.CertID)
			fmt.Printf("name:       %s\n", resolvedName)
			fmt.Printf("mode:       %s\n", sh.Mode)
			fmt.Printf("expires:    %s\n", sh.ExpiresAt.Format(time.RFC3339))
			if maxViews > 0 {
				fmt.Printf("max views:  %d\n", maxViews)
			}
			if baseURL != "" {
				fmt.Printf("url:        %s/share/%s\n", strings.TrimRight(baseURL, "/"), sh.ShareToken)
			} else {
				fmt.Printf("token:      %s\n", sh.ShareToken)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "certificate kind: public or private")
	cmd.Flags().StringVar(&name, "name", "", "certificate common name or SAN")
	cmd.Flags().StringVar(&mode, "mode", "cert", "share mode: cert or cert_key")
	cmd.Flags().StringVar(&sharePassword, "share-password", "", "password required to access the share")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "second password required to reveal the private key when mode=cert_key")
	cmd.Flags().StringVar(&expiresInRaw, "expires-in", "7d", "share expiry, e.g. 1d, 7d, 12h")
	cmd.Flags().Int64Var(&maxViews, "max-views", 0, "optional maximum number of views")
	cmd.Flags().StringVar(&note, "note", "", "optional note")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "optional base URL used to print a full share URL")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")

	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("name")
	rootCmd.AddCommand(cmd)
}
