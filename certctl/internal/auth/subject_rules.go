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
