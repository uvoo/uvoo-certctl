package auth

import (
	"context"
	"errors"
	"slices"
	"strings"

	"uvoocertctl/internal/storage"
)

type Identity struct {
	AuthMethod string
	Superuser  bool
	Issuer     string
	Subject    string
	Username   string
	Email      string
	Roles      []string
	Groups     []string
	LocalRoles  []string
	LocalGroups []string
	Principals []string
	RawClaims  map[string]any
}

type PermissionRequest struct {
	Permission   string
	ResourceKind string
	ResourceRef  string
}

type contextKey string

const identityContextKey contextKey = "uvoocertctl_auth_identity"

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityContextKey, identity)
}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey).(Identity)
	return identity, ok
}

func SuperuserIdentity(username string) Identity {
	username = strings.TrimSpace(username)
	return Identity{
		AuthMethod: "basic",
		Superuser:  true,
		Username:   username,
		Principals: []string{"superuser"},
	}
}

var ErrSubjectDisabled = errors.New("subject is locally disabled")
var ErrSubjectPending = errors.New("subject is pending local approval")

func ApplySubjectRecord(identity Identity, subject storage.Subject) Identity {
	identity.LocalRoles = append([]string(nil), subject.LocalRoles...)
	identity.LocalGroups = append([]string(nil), subject.LocalGroups...)
	identity.Principals = append(identity.Principals, localPrincipals(subject.LocalRoles, subject.LocalGroups)...)
	identity.Principals = uniqueStrings(identity.Principals...)
	return identity
}

func Allowed(identity Identity, bindings []storage.AuthzBinding, req PermissionRequest) bool {
	return len(MatchingBindings(identity, bindings, req)) > 0
}

func MatchingBindings(identity Identity, bindings []storage.AuthzBinding, req PermissionRequest) []storage.AuthzBinding {
	if identity.Superuser {
		return []storage.AuthzBinding{{
			ID:         "superuser",
			Enabled:    true,
			Principal:  "superuser",
			Permission: "*",
		}}
	}
	principals := map[string]struct{}{}
	for _, principal := range identity.Principals {
		principals[principal] = struct{}{}
	}

	var matched []storage.AuthzBinding
	for _, binding := range bindings {
		if !binding.Enabled {
			continue
		}
		if _, ok := principals[binding.Principal]; !ok {
			continue
		}
		if binding.Permission != "*" && binding.Permission != req.Permission {
			continue
		}
		if !matchesScope(binding.ResourceKind, req.ResourceKind) {
			continue
		}
		if !matchesScope(binding.ResourceRef, req.ResourceRef) {
			continue
		}
		matched = append(matched, binding)
	}
	return matched
}

func matchesScope(bindingValue, requestValue string) bool {
	bindingValue = strings.TrimSpace(bindingValue)
	requestValue = strings.TrimSpace(requestValue)
	switch bindingValue {
	case "", "*":
		return true
	default:
		return bindingValue == requestValue
	}
}

func EffectivePermissions(identity Identity, bindings []storage.AuthzBinding) []string {
	if identity.Superuser {
		return []string{"*"}
	}
	permissions := map[string]struct{}{}
	principals := map[string]struct{}{}
	for _, principal := range identity.Principals {
		principals[principal] = struct{}{}
	}
	for _, binding := range bindings {
		if !binding.Enabled {
			continue
		}
		if _, ok := principals[binding.Principal]; !ok {
			continue
		}
		permissions[binding.Permission] = struct{}{}
	}
	out := make([]string, 0, len(permissions))
	for permission := range permissions {
		out = append(out, permission)
	}
	slices.Sort(out)
	return out
}

func localPrincipals(localRoles, localGroups []string) []string {
	var principals []string
	for _, role := range localRoles {
		role = strings.TrimSpace(role)
		if role != "" {
			principals = append(principals, "local_role:"+role)
		}
	}
	for _, group := range localGroups {
		group = strings.TrimSpace(group)
		if group != "" {
			principals = append(principals, "local_group:"+group)
		}
	}
	return uniqueStrings(principals...)
}
