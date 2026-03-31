package cmd

import "certctl/internal/storage"

func subjectPayload(rec storage.Subject) map[string]any {
	return map[string]any{
		"id":            rec.ID,
		"issuer":        rec.Issuer,
		"subject":       rec.Subject,
		"status":        rec.Status,
		"username":      emptyStringToNil(rec.Username),
		"email":         emptyStringToNil(rec.Email),
		"roles":         rec.Roles,
		"groups":        rec.Groups,
		"auth_count":    rec.AuthCount,
		"first_seen_at": formatTimeValue(rec.FirstSeenAt),
		"last_seen_at":  formatTimeValue(rec.LastSeenAt),
		"updated_at":    formatTimeValue(rec.UpdatedAt),
	}
}
