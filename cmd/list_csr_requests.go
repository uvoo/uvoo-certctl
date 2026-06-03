package cmd

import (
	"fmt"
	"time"

	"uvoo-certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var id string
	var kind string
	var status string
	var all bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list-csr-requests",
		Short: "List queued CSR requests",
		Example: `  uvoo-certctl list-csr-requests
  uvoo-certctl list-csr-requests --all
  uvoo-certctl list-csr-requests --id <request-id> --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if id != "" {
				req, err := store.GetCSRRequestByID(id)
				if err != nil {
					return err
				}
				if jsonOut {
					return printJSON(csrRequestPayload(req, true))
				}
				printCSRRequest(req, true)
				return nil
			}

			effectiveStatus := status
			if !all && effectiveStatus == "" {
				effectiveStatus = storage.CSRStatusPending
			}

			rows, err := store.ListCSRRequests(kind, effectiveStatus)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Println("No CSR requests found")
				return nil
			}

			if jsonOut {
				payload := make([]map[string]any, 0, len(rows))
				for _, req := range rows {
					payload = append(payload, csrRequestPayload(req, false))
				}
				return printJSON(payload)
			}

			for _, req := range rows {
				printCSRRequest(req, false)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "specific CSR request id")
	cmd.Flags().StringVar(&kind, "kind", "", "filter by csr kind: public or private")
	cmd.Flags().StringVar(&status, "status", "", "filter by csr status: pending, issued, rejected")
	cmd.Flags().BoolVar(&all, "all", false, "include issued and rejected requests when --status is not set")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}

func printCSRRequest(req storage.CSRRequest, includeCSR bool) {
	printKV("id", req.ID)
	printKV("kind", req.Kind)
	printKV("status", req.Status)
	printKV("common_name", req.CommonName)
	printKV("sans", req.SANsCSV)
	printKV("requester_name", req.RequesterName)
	printKV("requester_email", req.RequesterEmail)
	printKV("phone_number", req.PhoneNumber)
	printKV("organization", req.Organization)
	printKV("department", req.Department)
	printKV("requested_ca_name", req.RequestedCAName)
	if req.CertType != "" {
		printKV("cert_type", req.CertType)
	}
	if req.RequestedDays > 0 {
		printKV("requested_days", fmt.Sprintf("%d", req.RequestedDays))
	}
	if req.IssuedCertID != "" {
		printKV("issued_cert_id", req.IssuedCertID)
	}
	if req.DecisionNote != "" {
		printKV("decision_note", req.DecisionNote)
	}
	if !req.ReviewedAt.IsZero() {
		printKV("reviewed_at", req.ReviewedAt.Format(time.RFC3339))
	}
	if includeCSR {
		fmt.Println("--- CSR ---")
		fmt.Print(string(req.CSRPEM))
	}
	fmt.Println()
}
