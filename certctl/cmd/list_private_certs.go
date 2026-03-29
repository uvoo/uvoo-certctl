package cmd

import (
	"database/sql"
	"fmt"
	"time"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var commonName string

	cmd := &cobra.Command{
		Use:   "list-private-certs",
		Short: "List stored private leaf certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.ListPrivateCerts(commonName)
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

			for _, r := range rows {
				fmt.Printf("id:              %s\n", r.ID)
				fmt.Printf("commonName:      %s\n", r.CommonName)
				fmt.Printf("domains:         %s\n", r.DomainsCSV)
				fmt.Printf("certType:        %s\n", r.CertType)
				fmt.Printf("keyType:         %s\n", r.KeyType)
				fmt.Printf("intermediate id: %s\n", r.IntermediateCAID)
				fmt.Printf("issuer:          %s\n", r.Issuer)
				fmt.Printf("notBefore:       %s\n", r.NotBefore.Format(time.RFC3339))
				fmt.Printf("notAfter:        %s\n", r.NotAfter.Format(time.RFC3339))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&commonName, "common-name", "", "filter by common name")
	rootCmd.AddCommand(cmd)
}

// quiet import guard if needed
var _ sql.NullString
