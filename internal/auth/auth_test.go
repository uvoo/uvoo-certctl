package auth

import (
	"testing"

	"uvoo-certctl/internal/storage"
)

func TestEffectivePermissionsAndMatchingBindings(t *testing.T) {
	identity := Identity{
		Issuer:     "https://issuer.example.test",
		Subject:    "user-1",
		Principals: []string{"sub:https://issuer.example.test:user-1", "role:https://issuer.example.test:uvoo-certctl_admin"},
	}
	bindings := []storage.AuthzBinding{
		{
			ID:         "binding-1",
			Enabled:    true,
			Principal:  "role:https://issuer.example.test:uvoo-certctl_admin",
			Permission: "doctor.read",
		},
		{
			ID:           "binding-2",
			Enabled:      true,
			Principal:    "role:https://issuer.example.test:uvoo-certctl_admin",
			Permission:   "csr.approve",
			ResourceKind: "csr_request",
			ResourceRef:  "*",
		},
		{
			ID:         "binding-3",
			Enabled:    false,
			Principal:  "role:https://issuer.example.test:uvoo-certctl_admin",
			Permission: "metrics.read",
		},
	}

	perms := EffectivePermissions(identity, bindings)
	if len(perms) != 2 || perms[0] != "csr.approve" || perms[1] != "doctor.read" {
		t.Fatalf("unexpected effective permissions: %+v", perms)
	}

	matches := MatchingBindings(identity, bindings, PermissionRequest{
		Permission:   "csr.approve",
		ResourceKind: "csr_request",
		ResourceRef:  "csr-1",
	})
	if len(matches) != 1 || matches[0].ID != "binding-2" {
		t.Fatalf("unexpected matching bindings: %+v", matches)
	}

	if !Allowed(identity, bindings, PermissionRequest{Permission: "doctor.read"}) {
		t.Fatal("expected doctor.read to be allowed")
	}
	if Allowed(identity, bindings, PermissionRequest{Permission: "metrics.read"}) {
		t.Fatal("expected metrics.read to be denied")
	}
}

func TestPreviewSubjectAccessAutoApprovesPendingMatch(t *testing.T) {
	identity := Identity{
		AuthMethod: "bearer",
		Issuer:     "https://accounts.google.com",
		Subject:    "user-1",
		Email:      "alice@example.com",
		Principals: []string{"sub:https://accounts.google.com:user-1"},
	}
	subject := storage.Subject{
		Issuer:  identity.Issuer,
		Subject: identity.Subject,
		Status:  storage.SubjectStatusPending,
	}
	preview := PreviewSubjectAccess(identity, &subject, []storage.SubjectAutoApprovalRule{
		{
			Name:        "google-employees",
			Enabled:     true,
			Issuer:      identity.Issuer,
			EmailDomain: "example.com",
			LocalGroups: []string{"employees"},
		},
	})

	if preview.Status != storage.SubjectStatusActive || preview.Reason != "auto_approved" {
		t.Fatalf("expected auto-approved active subject, got status=%s reason=%s", preview.Status, preview.Reason)
	}
	if len(preview.MatchedRuleNames) != 1 || preview.MatchedRuleNames[0] != "google-employees" {
		t.Fatalf("unexpected matched rules: %+v", preview.MatchedRuleNames)
	}
	if len(preview.Identity.LocalGroups) != 1 || preview.Identity.LocalGroups[0] != "employees" {
		t.Fatalf("unexpected local groups: %+v", preview.Identity.LocalGroups)
	}
}

func TestPreviewSubjectAccessPreservesDisabledSubject(t *testing.T) {
	identity := Identity{
		AuthMethod: "bearer",
		Issuer:     "https://accounts.google.com",
		Subject:    "user-1",
		Email:      "alice@example.com",
		Principals: []string{"sub:https://accounts.google.com:user-1"},
	}
	subject := storage.Subject{
		Issuer:      identity.Issuer,
		Subject:     identity.Subject,
		Status:      storage.SubjectStatusDisabled,
		LocalGroups: []string{"employees"},
	}
	preview := PreviewSubjectAccess(identity, &subject, []storage.SubjectAutoApprovalRule{
		{
			Name:        "google-employees",
			Enabled:     true,
			Issuer:      identity.Issuer,
			EmailDomain: "example.com",
			LocalGroups: []string{"ops"},
		},
	})

	if preview.Status != storage.SubjectStatusDisabled || preview.Reason != "disabled" {
		t.Fatalf("expected disabled preview, got status=%s reason=%s", preview.Status, preview.Reason)
	}
	if len(preview.MatchedRuleNames) != 0 {
		t.Fatalf("expected no matched rules for disabled subject, got %+v", preview.MatchedRuleNames)
	}
	if len(preview.Identity.LocalGroups) != 1 || preview.Identity.LocalGroups[0] != "employees" {
		t.Fatalf("expected existing local groups to be preserved, got %+v", preview.Identity.LocalGroups)
	}
}
