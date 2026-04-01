package auth

import (
	"strings"

	"certctl/internal/storage"
)

type SubjectAutoApprovalMatch struct {
	RuleNames   []string
	LocalRoles  []string
	LocalGroups []string
}

type SubjectAccessPreview struct {
	Status             string
	Reason             string
	MatchedRuleNames   []string
	MatchedLocalRoles  []string
	MatchedLocalGroups []string
	Identity           Identity
}

func MatchSubjectAutoApprovalRules(identity Identity, rules []storage.SubjectAutoApprovalRule) SubjectAutoApprovalMatch {
	var match SubjectAutoApprovalMatch
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if strings.TrimSpace(rule.Issuer) != identity.Issuer {
			continue
		}
		if !matchesEmailDomain(identity.Email, rule.EmailDomain) {
			continue
		}
		if !containsAll(identity.Roles, rule.RequiredRoles) {
			continue
		}
		if !containsAll(identity.Groups, rule.RequiredGroups) {
			continue
		}
		match.RuleNames = append(match.RuleNames, strings.TrimSpace(rule.Name))
		match.LocalRoles = append(match.LocalRoles, rule.LocalRoles...)
		match.LocalGroups = append(match.LocalGroups, rule.LocalGroups...)
	}
	match.RuleNames = uniqueStrings(match.RuleNames...)
	match.LocalRoles = uniqueStrings(match.LocalRoles...)
	match.LocalGroups = uniqueStrings(match.LocalGroups...)
	return match
}

func PreviewSubjectAccess(identity Identity, subject *storage.Subject, rules []storage.SubjectAutoApprovalRule) SubjectAccessPreview {
	preview := SubjectAccessPreview{
		Status:   storage.SubjectStatusPending,
		Reason:   "pending_local_approval",
		Identity: identity,
	}
	if subject != nil {
		preview.Status = subject.Status
		preview.Identity = ApplySubjectRecord(identity, *subject)
		switch subject.Status {
		case storage.SubjectStatusDisabled:
			preview.Reason = "disabled"
			return preview
		case storage.SubjectStatusActive:
			preview.Reason = "active"
			return preview
		default:
			preview.Reason = "pending_local_approval"
		}
	}

	match := MatchSubjectAutoApprovalRules(identity, rules)
	preview.MatchedRuleNames = append([]string(nil), match.RuleNames...)
	preview.MatchedLocalRoles = append([]string(nil), match.LocalRoles...)
	preview.MatchedLocalGroups = append([]string(nil), match.LocalGroups...)
	if len(match.RuleNames) == 0 {
		return preview
	}

	preview.Status = storage.SubjectStatusActive
	preview.Reason = "auto_approved"
	if subject != nil {
		preview.Identity.LocalRoles = uniqueStrings(append(append([]string(nil), subject.LocalRoles...), match.LocalRoles...)...)
		preview.Identity.LocalGroups = uniqueStrings(append(append([]string(nil), subject.LocalGroups...), match.LocalGroups...)...)
	} else {
		preview.Identity.LocalRoles = uniqueStrings(match.LocalRoles...)
		preview.Identity.LocalGroups = uniqueStrings(match.LocalGroups...)
	}
	preview.Identity.Principals = uniqueStrings(append(append([]string(nil), identity.Principals...), localPrincipals(preview.Identity.LocalRoles, preview.Identity.LocalGroups)...)...)
	return preview
}

func matchesEmailDomain(email, domain string) bool {
	domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "@")
	if domain == "" {
		return true
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}
	return strings.HasSuffix(email, "@"+domain)
}

func containsAll(values, required []string) bool {
	if len(required) == 0 {
		return true
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	for _, need := range required {
		need = strings.TrimSpace(need)
		if need == "" {
			continue
		}
		if _, ok := seen[need]; !ok {
			return false
		}
	}
	return true
}
