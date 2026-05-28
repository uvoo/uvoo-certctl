package cmd

import (
	"fmt"
	"io"
	"os"

	"uvoocertctl/internal/ops"
	"uvoocertctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var kind string
	var csrFile string
	var requesterName string
	var requesterEmail string
	var phoneNumber string
	var organization string
	var department string
	var note string
	var requestedCAName string
	var certType string
	var requestedDays int
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "submit-csr",
		Short: "Submit a public or private CSR into the approval queue",
		Example: `  uvoocertctl submit-csr \
    --kind private \
    --csr-file server.csr \
    --requester-name "Jane Doe" \
    --requester-email jane@example.com \
    --phone-number "+1-555-0100" \
    --organization Uvoo \
    --department Platform \
    --requested-ca-name corp-issuing \
    --cert-type server`,
		RunE: func(cmd *cobra.Command, args []string) error {
			csrData, err := readCSRInput(csrFile)
			if err != nil {
				return err
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			result, err := ops.SubmitCSR(store, ops.SubmitCSRParams{
				Kind:            kind,
				CSRData:         csrData,
				RequesterName:   requesterName,
				RequesterEmail:  requesterEmail,
				PhoneNumber:     phoneNumber,
				Organization:    organization,
				Department:      department,
				Note:            note,
				RequestedCAName: requestedCAName,
				CertType:        certType,
				RequestedDays:   requestedDays,
			})
			if err != nil {
				return err
			}

			if jsonOut {
				payload := csrRequestPayload(result.Request, false)
				payload["pickup_token"] = result.PickupToken
				return printJSON(payload)
			}

			fmt.Println("CSR request submitted")
			printKV("id", result.Request.ID)
			printKV("kind", result.Request.Kind)
			printKV("status", result.Request.Status)
			printKV("common_name", result.Request.CommonName)
			printKV("sans", result.Request.SANsCSV)
			printKV("pickup_token", result.PickupToken)
			return nil
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "csr kind: public or private")
	cmd.Flags().StringVar(&csrFile, "csr-file", "", "path to the CSR file, or - to read from stdin")
	cmd.Flags().StringVar(&requesterName, "requester-name", "", "requester name")
	cmd.Flags().StringVar(&requesterEmail, "requester-email", "", "requester email")
	cmd.Flags().StringVar(&phoneNumber, "phone-number", "", "requester phone number")
	cmd.Flags().StringVar(&organization, "organization", "", "requester organization or company")
	cmd.Flags().StringVar(&department, "department", "", "requester department, desk, or team")
	cmd.Flags().StringVar(&note, "note", "", "optional request note")
	cmd.Flags().StringVar(&requestedCAName, "requested-ca-name", "", "optional requested issuing CA logical name for private requests")
	cmd.Flags().StringVar(&certType, "cert-type", "", "optional private cert type: server, client, or server_client")
	cmd.Flags().IntVar(&requestedDays, "days", 0, "optional requested validity in days")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")

	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("csr-file")
	rootCmd.AddCommand(cmd)
}

func readCSRInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}
