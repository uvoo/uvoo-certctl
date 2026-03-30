package cmd

import (
	"fmt"
	"os"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var outPath string
	var force bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "backup-db",
		Short: "Create a SQLite backup of the certificate database",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(outPath); err == nil {
				if !force {
					return fmt.Errorf("backup file already exists: %s", outPath)
				}
				if err := os.Remove(outPath); err != nil {
					return err
				}
			}

			store, err := storage.Open(rootCfg.DBPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if err := store.BackupTo(outPath); err != nil {
				return err
			}
			logAuditEvent(store, "backup_db", "database", rootCfg.DBPath, outPath)
			if jsonOut {
				return printJSON(map[string]any{
					"database": rootCfg.DBPath,
					"backup":   outPath,
				})
			}
			fmt.Printf("Database backup written to %s\n", outPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&outPath, "out", "", "backup database path")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing backup file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("out")
	rootCmd.AddCommand(cmd)
}
