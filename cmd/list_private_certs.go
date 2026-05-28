package cmd

import (
	"database/sql"
	"fmt"
	"time"

	"uvoocertctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var commonName string
	var all bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-private-certs",
		Short: "List stored private leaf certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.ListPrivateCerts(commonName, all)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				if commonName != "" {
					fmt.Printf("No private certificates found for common name: %s\n", commonName)
				} else {
					fmt.Println("No private certificates found")
				}
				return nil
			}
			if jsonOut {
				var payload []map[string]any
				for _, r := range rows {
					payload = append(payload, map[string]any{
						"id":                 r.ID,
						"intermediate_ca_id": r.IntermediateCAID,
						"common_name":        r.CommonName,
						"sans_csv":           r.SANsCSV,
						"cert_type":          r.CertType,
						"key_type":           r.KeyType,
						"issuer":             r.Issuer,
						"status":             r.Status,
						"supersedes_cert_id": r.SupersedesCertID,
						"revoked_at":         formatTimeValue(r.RevokedAt),
						"not_before":         formatTimeValue(r.NotBefore),
						"not_after":          formatTimeValue(r.NotAfter),
						"created_at":         formatTimeValue(r.CreatedAt),
						"updated_at":         formatTimeValue(r.UpdatedAt),
						"private_key_stored": privateKeyStored(r.KeyPEM),
					})
				}
				return printJSON(payload)
			}

			for _, r := range rows {
				fmt.Printf("id:              %s\n", r.ID)
				fmt.Printf("status:          %s\n", r.Status)
				fmt.Printf("commonName:      %s\n", r.CommonName)
				fmt.Printf("sans:         %s\n", r.SANsCSV)
				fmt.Printf("certType:        %s\n", r.CertType)
				fmt.Printf("keyType:         %s\n", r.KeyType)
				fmt.Printf("keyStored:       %t\n", privateKeyStored(r.KeyPEM))
				fmt.Printf("intermediate id: %s\n", r.IntermediateCAID)
				fmt.Printf("issuer:          %s\n", r.Issuer)
				fmt.Printf("notBefore:       %s\n", r.NotBefore.Format(time.RFC3339))
				fmt.Printf("notAfter:        %s\n", r.NotAfter.Format(time.RFC3339))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&commonName, "common-name", "", "filter by common name")
	cmd.Flags().BoolVar(&all, "all", false, "include inactive and historical certificates")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}

// quiet import guard if needed
var _ sql.NullString
