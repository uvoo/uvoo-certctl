package cmd

import "uvoo-certctl/internal/storage"

func subjectAutoApprovalRulePayload(rec storage.SubjectAutoApprovalRule) map[string]any {
	return map[string]any{
		"id":              rec.ID,
		"name":            rec.Name,
		"enabled":         rec.Enabled,
		"issuer":          rec.Issuer,
		"email_domain":    emptyStringToNil(rec.EmailDomain),
		"required_roles":  rec.RequiredRoles,
		"required_groups": rec.RequiredGroups,
		"local_roles":     rec.LocalRoles,
		"local_groups":    rec.LocalGroups,
		"created_at":      formatTimeValue(rec.CreatedAt),
		"updated_at":      formatTimeValue(rec.UpdatedAt),
	}
}
