package auth

import (
	"testing"

	"certctl/internal/storage"
)

func TestEffectivePermissionsAndMatchingBindings(t *testing.T) {
	identity := Identity{
		Issuer:     "https://issuer.example.test",
		Subject:    "user-1",
		Principals: []string{"sub:https://issuer.example.test:user-1", "role:https://issuer.example.test:certctl_admin"},
	}
	bindings := []storage.AuthzBinding{
		{
			ID:         "binding-1",
			Enabled:    true,
			Principal:  "role:https://issuer.example.test:certctl_admin",
			Permission: "doctor.read",
		},
		{
			ID:           "binding-2",
			Enabled:      true,
			Principal:    "role:https://issuer.example.test:certctl_admin",
			Permission:   "csr.approve",
			ResourceKind: "csr_request",
			ResourceRef:  "*",
		},
		{
			ID:         "binding-3",
			Enabled:    false,
			Principal:  "role:https://issuer.example.test:certctl_admin",
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
