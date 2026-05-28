package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"certctl/internal/storage"
	"github.com/spf13/cobra"
)

func init() {
	var fromPath string
	var force bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "restore-db",
		Short: "Restore the certificate database from a backup file",
		Example: `  certctl restore-db --from certctl-backup.db --force
  certctl restore-db --from /secure/backups/certctl.db --force --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fromAbs, err := filepath.Abs(fromPath)
			if err != nil {
				return err
			}
			targetAbs, err := filepath.Abs(rootCfg.DBPath)
			if err != nil {
				return err
			}
			if fromAbs == targetAbs {
				return fmt.Errorf("--from must be different from the live database path")
			}

			if _, err := os.Stat(fromAbs); err != nil {
				return err
			}
			if _, err := os.Stat(targetAbs); err == nil && !force {
				return fmt.Errorf("live database exists; rerun with --force to restore over it")
			}

			validationStore, err := storage.Open(fromAbs)
			if err != nil {
				return fmt.Errorf("backup database failed validation: %w", err)
			}
			_ = validationStore.Close()

			dir := filepath.Dir(targetAbs)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}

			timestamp := time.Now().UTC().Format("20060102T150405Z")
			safetyBackup := targetAbs + ".pre-restore-" + timestamp + ".bak"
			tmpRestore := targetAbs + ".restore.tmp"
			createdSafetyBackup := false

			_ = os.Remove(tmpRestore)
			if err := copyFile(fromAbs, tmpRestore, 0o600); err != nil {
				return err
			}

			if _, err := os.Stat(targetAbs); err == nil {
				currentStore, err := storage.Open(targetAbs)
				if err != nil {
					return err
				}
				if err := currentStore.BackupTo(safetyBackup); err != nil {
					_ = currentStore.Close()
					return err
				}
				createdSafetyBackup = true
				logAuditEvent(currentStore, "restore_db_safety_backup", "database", targetAbs, safetyBackup)
				_ = currentStore.Close()

				_ = os.Remove(targetAbs + "-wal")
				_ = os.Remove(targetAbs + "-shm")
				if err := os.Remove(targetAbs); err != nil {
					return err
				}
			}

			if err := os.Rename(tmpRestore, targetAbs); err != nil {
				return err
			}
			_ = os.Remove(targetAbs + "-wal")
			_ = os.Remove(targetAbs + "-shm")

			liveStore, err := storage.Open(targetAbs)
			if err != nil {
				return err
			}
			logAuditEvent(liveStore, "restore_db", "database", targetAbs, fromAbs)
			_ = liveStore.Close()

			if jsonOut {
				payload := map[string]any{
					"database":      targetAbs,
					"restored_from": fromAbs,
				}
				if createdSafetyBackup {
					payload["safety_backup"] = safetyBackup
				}
				return printJSON(payload)
			}

			fmt.Printf("Database restored from %s\n", fromAbs)
			if createdSafetyBackup {
				fmt.Printf("Safety backup written to %s\n", safetyBackup)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&fromPath, "from", "", "path to the backup database file")
	cmd.Flags().BoolVar(&force, "force", false, "restore over the current live database")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON output")
	_ = cmd.MarkFlagRequired("from")
	rootCmd.AddCommand(cmd)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
