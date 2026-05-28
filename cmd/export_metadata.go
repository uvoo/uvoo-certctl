package cmd

import (
	"encoding/json"
	"os"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var outPath string

	cmd := &cobra.Command{
		Use:   "export-metadata",
		Short: "Export non-secret certificate metadata as JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			publicCerts, err := store.List("", true)
			if err != nil {
				return err
			}
			privateCerts, err := store.ListPrivateCerts("", true)
			if err != nil {
				return err
			}
			rootCAs, err := store.ListPrivateRootCAs("", true)
			if err != nil {
				return err
			}
			intermediateCAs, err := store.ListPrivateIntermediateCAs("", true)
			if err != nil {
				return err
			}
			shares, err := store.ListShares("")
			if err != nil {
				return err
			}

			payload := map[string]any{
				"public_certs":          exportPublicMetadata(publicCerts),
				"private_certs":         exportPrivateMetadata(privateCerts),
				"private_root_cas":      exportRootMetadata(rootCAs),
				"private_intermediates": exportIntermediateMetadata(intermediateCAs),
				"shares":                exportShareMetadata(shares),
			}

			if outPath == "" {
				return printJSON(payload)
			}

			f, err := os.Create(outPath)
			if err != nil {
				return err
			}
			defer f.Close()

			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			return enc.Encode(payload)
		},
	}

	cmd.Flags().StringVar(&outPath, "out", "", "write JSON to a file instead of stdout")
	rootCmd.AddCommand(cmd)
}

func exportPublicMetadata(rows []storage.PublicCert) []map[string]any {
	var out []map[string]any
	for _, row := range rows {
		out = append(out, map[string]any{
			"id":                 row.ID,
			"common_name":        row.CommonName,
			"sans_csv":           row.SANsCSV,
			"provider":           row.Provider,
			"email":              row.Email,
			"issuer":             row.Issuer,
			"status":             row.Status,
			"supersedes_cert_id": row.SupersedesCertID,
			"revoked_at":         formatTimeValue(row.RevokedAt),
			"not_before":         formatTimeValue(row.NotBefore),
			"not_after":          formatTimeValue(row.NotAfter),
			"created_at":         formatTimeValue(row.CreatedAt),
			"updated_at":         formatTimeValue(row.UpdatedAt),
		})
	}
	return out
}

func exportPrivateMetadata(rows []storage.PrivateCert) []map[string]any {
	var out []map[string]any
	for _, row := range rows {
		out = append(out, map[string]any{
			"id":                 row.ID,
			"intermediate_ca_id": row.IntermediateCAID,
			"common_name":        row.CommonName,
			"sans_csv":           row.SANsCSV,
			"cert_type":          row.CertType,
			"key_type":           row.KeyType,
			"issuer":             row.Issuer,
			"status":             row.Status,
			"supersedes_cert_id": row.SupersedesCertID,
			"revoked_at":         formatTimeValue(row.RevokedAt),
			"not_before":         formatTimeValue(row.NotBefore),
			"not_after":          formatTimeValue(row.NotAfter),
			"created_at":         formatTimeValue(row.CreatedAt),
			"updated_at":         formatTimeValue(row.UpdatedAt),
		})
	}
	return out
}

func exportRootMetadata(rows []storage.PrivateRootCA) []map[string]any {
	var out []map[string]any
	for _, row := range rows {
		out = append(out, map[string]any{
			"id":               row.ID,
			"name":             row.Name,
			"common_name":      row.CommonName,
			"generation":       row.Generation,
			"status":           row.Status,
			"is_trusted":       row.IsTrusted,
			"is_issuing":       row.IsIssuing,
			"supersedes_ca_id": row.SupersedesCAID,
			"key_type":         row.KeyType,
			"issuer":           row.Issuer,
			"not_before":       formatTimeValue(row.NotBefore),
			"not_after":        formatTimeValue(row.NotAfter),
			"created_at":       formatTimeValue(row.CreatedAt),
			"updated_at":       formatTimeValue(row.UpdatedAt),
		})
	}
	return out
}

func exportIntermediateMetadata(rows []storage.PrivateIntermediateCA) []map[string]any {
	var out []map[string]any
	for _, row := range rows {
		out = append(out, map[string]any{
			"id":               row.ID,
			"root_ca_id":       row.RootCAID,
			"name":             row.Name,
			"common_name":      row.CommonName,
			"generation":       row.Generation,
			"status":           row.Status,
			"is_trusted":       row.IsTrusted,
			"is_issuing":       row.IsIssuing,
			"supersedes_ca_id": row.SupersedesCAID,
			"key_type":         row.KeyType,
			"issuer":           row.Issuer,
			"not_before":       formatTimeValue(row.NotBefore),
			"not_after":        formatTimeValue(row.NotAfter),
			"created_at":       formatTimeValue(row.CreatedAt),
			"updated_at":       formatTimeValue(row.UpdatedAt),
		})
	}
	return out
}

func exportShareMetadata(rows []storage.CertShare) []map[string]any {
	var out []map[string]any
	for _, row := range rows {
		out = append(out, map[string]any{
			"id":             row.ID,
			"cert_kind":      row.CertKind,
			"cert_id":        row.CertID,
			"mode":           row.Mode,
			"expires_at":     formatTimeValue(row.ExpiresAt),
			"max_views":      nullableInt64Value(row.MaxViews),
			"view_count":     row.ViewCount,
			"created_at":     formatTimeValue(row.CreatedAt),
			"last_viewed_at": formatTimeValue(row.LastViewedAt),
			"revoked_at":     formatTimeValue(row.RevokedAt),
			"note":           row.Note,
		})
	}
	return out
}
