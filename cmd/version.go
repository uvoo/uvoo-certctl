package cmd

import "github.com/spf13/cobra"

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func init() {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Example: `  uvoocertctl version
  uvoocertctl version --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			payload := map[string]any{
				"version": version,
				"commit":  commit,
				"date":    date,
			}
			if jsonOut {
				return printJSON(payload)
			}

			printKV("version", version)
			printKV("commit", commit)
			printKV("date", date)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	rootCmd.AddCommand(cmd)
}
