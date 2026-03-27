package cmd

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"certctl/internal/storage"
	"certctl/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	var domain string
	var mode string
	var sharePassword string
	var keyPassword string
	var expiresInRaw string
	var maxViews int64
	var note string
	var baseURL string

	cmd := &cobra.Command{
		Use:   "share-cert",
		Short: "Create a share URL for a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if mode != "cert" && mode != "cert_key" {
				return fmt.Errorf("--mode must be cert or cert_key")
			}
			if sharePassword == "" {
				return fmt.Errorf("--share-password is required")
			}
			if mode == "cert_key" && keyPassword == "" {
				return fmt.Errorf("--key-password is required when --mode=cert_key")
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rec, err := store.GetByDomain(domain)
			if err != nil {
				return fmt.Errorf("certificate not found for domain %q: %w", domain, err)
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
				CertID:            rec.ID,
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

			fmt.Println("Share created")
			fmt.Printf("share id: %s\n", sh.ID)
			fmt.Printf("cert id:  %s\n", rec.ID)
			fmt.Printf("mode:     %s\n", sh.Mode)
			fmt.Printf("expires:  %s\n", sh.ExpiresAt.Format(time.RFC3339))
			if maxViews > 0 {
				fmt.Printf("max views: %d\n", maxViews)
			}
			if baseURL != "" {
				fmt.Printf("url: %s/share/%s\n", strings.TrimRight(baseURL, "/"), sh.ShareToken)
			} else {
				fmt.Printf("token: %s\n", sh.ShareToken)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "primary or SAN domain to find the certificate")
	cmd.Flags().StringVar(&mode, "mode", "cert", "share mode: cert or cert_key")
	cmd.Flags().StringVar(&sharePassword, "share-password", "", "password required to access the share")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "second password required to reveal the private key when mode=cert_key")
	cmd.Flags().StringVar(&expiresInRaw, "expires-in", "7d", "share expiry, e.g. 1d, 7d, 12h")
	cmd.Flags().Int64Var(&maxViews, "max-views", 0, "optional maximum number of views")
	cmd.Flags().StringVar(&note, "note", "", "optional note")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "optional base URL used to print a full share URL")
	_ = cmd.MarkFlagRequired("domain")

	rootCmd.AddCommand(cmd)
}
