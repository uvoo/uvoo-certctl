package ops

import (
	"strings"

	"certctl/internal/storage"
	"certctl/internal/util"
)

type SubjectFilter struct {
	ActiveOnly bool
	Issuer     string
	Subject    string
	Status     string
	LocalRole  string
	LocalGroup string
}

func ListSubjects(store *storage.Store, filter SubjectFilter) ([]storage.Subject, error) {
	rows, err := store.ListSubjects(filter.ActiveOnly)
	if err != nil {
		return nil, err
	}

	out := make([]storage.Subject, 0, len(rows))
	for _, row := range rows {
		if filter.Issuer != "" && row.Issuer != strings.TrimSpace(filter.Issuer) {
			continue
		}
		if filter.Subject != "" && row.Subject != strings.TrimSpace(filter.Subject) {
			continue
		}
		if filter.Status != "" && row.Status != strings.TrimSpace(filter.Status) {
			continue
		}
		if filter.LocalRole != "" && !containsString(row.LocalRoles, filter.LocalRole) {
			continue
		}
		if filter.LocalGroup != "" && !containsString(row.LocalGroups, filter.LocalGroup) {
			continue
		}
		out = append(out, row)
	}
	return out, nil
}

func ApproveSubject(store *storage.Store, issuer, subject string, localRoles, localGroups []string, replaceRoles, replaceGroups bool) (storage.Subject, error) {
	rec, err := store.GetSubject(issuer, subject)
	if err != nil {
		return storage.Subject{}, err
	}

	roles := rec.LocalRoles
	if replaceRoles {
		roles = compactStrings(localRoles)
	}
	groups := rec.LocalGroups
	if replaceGroups {
		groups = compactStrings(localGroups)
	}

	if err := store.UpdateSubjectApproval(issuer, subject, storage.SubjectStatusActive, roles, groups); err != nil {
		return storage.Subject{}, err
	}
	rec, err = store.GetSubject(issuer, subject)
	if err != nil {
		return storage.Subject{}, err
	}
	LogAuditEvent(store, "approve_subject", "subject", rec.ID, rec.Issuer+" "+rec.Subject)
	return rec, nil
}

type UpdateSubjectParams struct {
	Issuer       string
	Subject      string
	Status       string
	LocalRoles   []string
	LocalGroups  []string
	ChangeStatus bool
	ChangeRoles  bool
	ChangeGroups bool
}

func UpdateSubject(store *storage.Store, params UpdateSubjectParams) (storage.Subject, error) {
	rec, err := store.GetSubject(params.Issuer, params.Subject)
	if err != nil {
		return storage.Subject{}, err
	}

	nextStatus := rec.Status
	if params.ChangeStatus {
		nextStatus = strings.TrimSpace(params.Status)
	}
	nextRoles := rec.LocalRoles
	if params.ChangeRoles {
		nextRoles = compactStrings(params.LocalRoles)
	}
	nextGroups := rec.LocalGroups
	if params.ChangeGroups {
		nextGroups = compactStrings(params.LocalGroups)
	}

	if err := store.UpdateSubjectApproval(params.Issuer, params.Subject, nextStatus, nextRoles, nextGroups); err != nil {
		return storage.Subject{}, err
	}
	rec, err = store.GetSubject(params.Issuer, params.Subject)
	if err != nil {
		return storage.Subject{}, err
	}
	LogAuditEvent(store, "update_subject", "subject", rec.ID, rec.Issuer+" "+rec.Subject)
	return rec, nil
}

type SubjectAutoApprovalRuleFilter struct {
	EnabledOnly bool
	Name        string
	Issuer      string
}

func ListSubjectAutoApprovalRules(store *storage.Store, filter SubjectAutoApprovalRuleFilter) ([]storage.SubjectAutoApprovalRule, error) {
	rows, err := store.ListSubjectAutoApprovalRules(filter.EnabledOnly)
	if err != nil {
		return nil, err
	}

	out := make([]storage.SubjectAutoApprovalRule, 0, len(rows))
	for _, row := range rows {
		if filter.Name != "" && row.Name != strings.TrimSpace(filter.Name) {
			continue
		}
		if filter.Issuer != "" && row.Issuer != strings.TrimSpace(filter.Issuer) {
			continue
		}
		out = append(out, row)
	}
	return out, nil
}

type UpsertSubjectAutoApprovalRuleParams struct {
	Name           string
	Enabled        bool
	Issuer         string
	EmailDomain    string
	RequiredRoles  []string
	RequiredGroups []string
	LocalRoles     []string
	LocalGroups    []string
}

func UpsertSubjectAutoApprovalRule(store *storage.Store, params UpsertSubjectAutoApprovalRuleParams) (storage.SubjectAutoApprovalRule, error) {
	if err := store.UpsertSubjectAutoApprovalRule(storage.SubjectAutoApprovalRule{
		ID:             util.NewID(),
		Name:           params.Name,
		Enabled:        params.Enabled,
		Issuer:         params.Issuer,
		EmailDomain:    params.EmailDomain,
		RequiredRoles:  compactStrings(params.RequiredRoles),
		RequiredGroups: compactStrings(params.RequiredGroups),
		LocalRoles:     compactStrings(params.LocalRoles),
		LocalGroups:    compactStrings(params.LocalGroups),
	}); err != nil {
		return storage.SubjectAutoApprovalRule{}, err
	}
	rec, err := store.GetSubjectAutoApprovalRuleByName(params.Name)
	if err != nil {
		return storage.SubjectAutoApprovalRule{}, err
	}
	LogAuditEvent(store, "upsert_subject_auto_approval", "subject_auto_approval_rule", rec.Name, rec.Issuer)
	return rec, nil
}

func DeleteSubjectAutoApprovalRule(store *storage.Store, name string) (storage.SubjectAutoApprovalRule, error) {
	rec, err := store.GetSubjectAutoApprovalRuleByName(name)
	if err != nil {
		return storage.SubjectAutoApprovalRule{}, err
	}
	if err := store.DeleteSubjectAutoApprovalRule(name); err != nil {
		return storage.SubjectAutoApprovalRule{}, err
	}
	LogAuditEvent(store, "delete_subject_auto_approval", "subject_auto_approval_rule", rec.Name, rec.Issuer)
	return rec, nil
}

func containsString(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func compactStrings(values []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
