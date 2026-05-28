package cmd

import (
	"fmt"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var kind string
	var name string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show certificate or CA lineage history",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			switch kind {
			case "public":
				rows, err := store.ListPublicCertHistory(name)
				if err != nil {
					return err
				}
				if jsonOut {
					var payload []map[string]any
					for _, row := range rows {
						payload = append(payload, map[string]any{
							"id":                 row.ID,
							"common_name":        row.CommonName,
							"sans_csv":           row.SANsCSV,
							"status":             row.Status,
							"supersedes_cert_id": row.SupersedesCertID,
							"revoked_at":         formatTimeValue(row.RevokedAt),
							"not_before":         formatTimeValue(row.NotBefore),
							"not_after":          formatTimeValue(row.NotAfter),
							"created_at":         formatTimeValue(row.CreatedAt),
							"updated_at":         formatTimeValue(row.UpdatedAt),
						})
					}
					return printJSON(payload)
				}
				for _, row := range rows {
					fmt.Printf("%s  %s  %s  supersedes=%s\n", row.ID, row.Status, formatTimeValue(row.NotAfter), row.SupersedesCertID)
				}
			case "private":
				rows, err := store.ListPrivateCertHistory(name)
				if err != nil {
					return err
				}
				if jsonOut {
					var payload []map[string]any
					for _, row := range rows {
						payload = append(payload, map[string]any{
							"id":                 row.ID,
							"common_name":        row.CommonName,
							"sans_csv":           row.SANsCSV,
							"cert_type":          row.CertType,
							"key_type":           row.KeyType,
							"status":             row.Status,
							"supersedes_cert_id": row.SupersedesCertID,
							"revoked_at":         formatTimeValue(row.RevokedAt),
							"not_before":         formatTimeValue(row.NotBefore),
							"not_after":          formatTimeValue(row.NotAfter),
							"created_at":         formatTimeValue(row.CreatedAt),
							"updated_at":         formatTimeValue(row.UpdatedAt),
						})
					}
					return printJSON(payload)
				}
				for _, row := range rows {
					fmt.Printf("%s  %s  %s  supersedes=%s\n", row.ID, row.Status, formatTimeValue(row.NotAfter), row.SupersedesCertID)
				}
			case "root":
				rows, err := store.ListPrivateRootCAs(name, true)
				if err != nil {
					return err
				}
				if jsonOut {
					var payload []map[string]any
					for _, row := range rows {
						payload = append(payload, map[string]any{
							"id":               row.ID,
							"name":             row.Name,
							"common_name":      row.CommonName,
							"generation":       row.Generation,
							"status":           row.Status,
							"is_trusted":       row.IsTrusted,
							"is_issuing":       row.IsIssuing,
							"supersedes_ca_id": row.SupersedesCAID,
							"key_type":         row.KeyType,
							"not_before":       formatTimeValue(row.NotBefore),
							"not_after":        formatTimeValue(row.NotAfter),
							"created_at":       formatTimeValue(row.CreatedAt),
							"updated_at":       formatTimeValue(row.UpdatedAt),
						})
					}
					return printJSON(payload)
				}
				for _, row := range rows {
					fmt.Printf("%s  gen=%d  %s  trusted=%t issuing=%t supersedes=%s\n", row.ID, row.Generation, row.Status, row.IsTrusted, row.IsIssuing, row.SupersedesCAID)
				}
			case "intermediate":
				rows, err := store.ListPrivateIntermediateCAs(name, true)
				if err != nil {
					return err
				}
				if jsonOut {
					var payload []map[string]any
					for _, row := range rows {
						payload = append(payload, map[string]any{
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
							"not_before":       formatTimeValue(row.NotBefore),
							"not_after":        formatTimeValue(row.NotAfter),
							"created_at":       formatTimeValue(row.CreatedAt),
							"updated_at":       formatTimeValue(row.UpdatedAt),
						})
					}
					return printJSON(payload)
				}
				for _, row := range rows {
					fmt.Printf("%s  gen=%d  %s  trusted=%t issuing=%t supersedes=%s\n", row.ID, row.Generation, row.Status, row.IsTrusted, row.IsIssuing, row.SupersedesCAID)
				}
			default:
				return fmt.Errorf("--kind must be one of public, private, root, intermediate")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "history kind: public, private, root, intermediate")
	cmd.Flags().StringVar(&name, "name", "", "common name or logical name")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("name")
	rootCmd.AddCommand(cmd)
}
