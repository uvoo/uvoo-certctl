package cmd

import (
	"database/sql"
	"encoding/json"
	"time"
)

func printJSON(v any) error {
	enc := json.NewEncoder(rootCmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func formatTimeValue(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func nullableInt64Value(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}
