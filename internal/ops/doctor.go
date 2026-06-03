package ops

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"uvoo-certctl/internal/auth"
	"uvoo-certctl/internal/storage"
)

type DoctorFinding struct {
	Severity string `json:"severity"`
	Check    string `json:"check"`
	Message  string `json:"message"`
}

type DoctorStore interface {
	List(string, bool) ([]storage.PublicCert, error)
	ListPrivateCerts(string, bool) ([]storage.PrivateCert, error)
	ListPrivateRootCAs(string, bool) ([]storage.PrivateRootCA, error)
	ListPrivateIntermediateCAs(string, bool) ([]storage.PrivateIntermediateCA, error)
	ListShares(string) ([]storage.CertShare, error)
	ListCSRRequests(string, string) ([]storage.CSRRequest, error)
	ListAuthIssuers(bool) ([]storage.AuthIssuer, error)
	ListAuthzBindings(bool) ([]storage.AuthzBinding, error)
	ListSubjectAutoApprovalRules(bool) ([]storage.SubjectAutoApprovalRule, error)
}

type AuthIssuerProbe func(storage.AuthIssuer) error

type DoctorOptions struct {
	WarnDays        int
	Now             time.Time
	AuthIssuerProbe AuthIssuerProbe
}

func RunDoctor(store DoctorStore, warnDays int) ([]DoctorFinding, error) {
	return RunDoctorWithOptions(store, DoctorOptions{
		WarnDays:        warnDays,
		Now:             time.Now().UTC(),
		AuthIssuerProbe: DefaultAuthIssuerProbe(10 * time.Second),
	})
}

func RunDoctorWithOptions(store DoctorStore, opts DoctorOptions) ([]DoctorFinding, error) {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	warnWindow := time.Duration(opts.WarnDays) * 24 * time.Hour
	var findings []DoctorFinding

	publicRows, err := store.List("", true)
	if err != nil {
		return nil, err
	}
	privateRows, err := store.ListPrivateCerts("", true)
	if err != nil {
		return nil, err
	}
	rootRows, err := store.ListPrivateRootCAs("", true)
	if err != nil {
		return nil, err
	}
	icaRows, err := store.ListPrivateIntermediateCAs("", true)
	if err != nil {
		return nil, err
	}
	shares, err := store.ListShares("")
	if err != nil {
		return nil, err
	}
	pendingCSRs, err := store.ListCSRRequests("", storage.CSRStatusPending)
	if err != nil {
		return nil, err
	}
	authIssuers, err := store.ListAuthIssuers(false)
	if err != nil {
		return nil, err
	}
	authzBindings, err := store.ListAuthzBindings(true)
	if err != nil {
		return nil, err
	}
	subjectAutoApprovalRules, err := store.ListSubjectAutoApprovalRules(false)
	if err != nil {
		return nil, err
	}

	findings = append(findings, checkActiveLeafCounts(publicRows, privateRows)...)
	findings = append(findings, checkLeafLineageLinks(publicRows, privateRows)...)
	findings = append(findings, checkCAInvariants(rootRows, icaRows, now)...)
	findings = append(findings, checkPrivateCertIssuers(privateRows, icaRows)...)
	findings = append(findings, checkAuthIssuerBindings(authIssuers, authzBindings, subjectAutoApprovalRules)...)
	findings = append(findings, checkBroadAuthzBindings(authzBindings)...)
	findings = append(findings, checkDuplicateAuthzBindings(authzBindings)...)
	findings = append(findings, checkSubjectAutoApprovalRules(authIssuers, subjectAutoApprovalRules)...)
	findings = append(findings, checkAuthIssuerDiscovery(authIssuers, authzBindings, opts.AuthIssuerProbe)...)
	if opts.WarnDays > 0 {
		findings = append(findings, checkExpiringLeafs(publicRows, privateRows, now, warnWindow)...)
		findings = append(findings, checkExpiringCAs(rootRows, icaRows, now, warnWindow)...)
		findings = append(findings, checkShares(shares, now, warnWindow)...)
		findings = append(findings, checkPendingCSRRequests(pendingCSRs, now, warnWindow)...)
	}

	return findings, nil
}

func DefaultAuthIssuerProbe(timeout time.Duration) AuthIssuerProbe {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	return func(issuer storage.AuthIssuer) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return auth.CheckIssuerConnectivity(ctx, client, issuer)
	}
}

func DoctorStatus(findings []DoctorFinding) string {
	status := "ok"
	for _, finding := range findings {
		if finding.Severity == "error" {
			return "error"
		}
		if finding.Severity == "warn" {
			status = "warn"
		}
	}
	return status
}

func FilterDoctorFindings(findings []DoctorFinding, keep func(DoctorFinding) bool) []DoctorFinding {
	if keep == nil {
		return append([]DoctorFinding(nil), findings...)
	}
	out := make([]DoctorFinding, 0, len(findings))
	for _, finding := range findings {
		if keep(finding) {
			out = append(out, finding)
		}
	}
	return out
}

func AuthRelatedDoctorFindings(findings []DoctorFinding) []DoctorFinding {
	return FilterDoctorFindings(findings, func(finding DoctorFinding) bool {
		check := strings.TrimSpace(finding.Check)
		return strings.HasPrefix(check, "auth_") ||
			strings.HasPrefix(check, "authz_") ||
			strings.HasPrefix(check, "subject_auto_approval_")
	})
}

func checkActiveLeafCounts(publicRows []storage.PublicCert, privateRows []storage.PrivateCert) []DoctorFinding {
	var findings []DoctorFinding
	publicCounts := map[string]int{}
	for _, row := range publicRows {
		if row.Status == storage.StatusActive {
			publicCounts[row.CommonName]++
		}
	}
	for commonName, count := range publicCounts {
		if count > 1 {
			findings = append(findings, DoctorFinding{
				Severity: "error",
				Check:    "public_active_count",
				Message:  fmt.Sprintf("%s has %d active public certs", commonName, count),
			})
		}
	}

	privateCounts := map[string]int{}
	for _, row := range privateRows {
		if row.Status == storage.StatusActive {
			privateCounts[row.CommonName]++
		}
	}
	for commonName, count := range privateCounts {
		if count > 1 {
			findings = append(findings, DoctorFinding{
				Severity: "error",
				Check:    "private_active_count",
				Message:  fmt.Sprintf("%s has %d active private certs", commonName, count),
			})
		}
	}
	return findings
}

func checkLeafLineageLinks(publicRows []storage.PublicCert, privateRows []storage.PrivateCert) []DoctorFinding {
	var findings []DoctorFinding

	publicIDs := map[string]struct{}{}
	for _, row := range publicRows {
		publicIDs[row.ID] = struct{}{}
	}
	for _, row := range publicRows {
		if row.SupersedesCertID != "" {
			if _, ok := publicIDs[row.SupersedesCertID]; !ok {
				findings = append(findings, DoctorFinding{
					Severity: "error",
					Check:    "public_lineage",
					Message:  fmt.Sprintf("public cert %s supersedes missing cert %s", row.ID, row.SupersedesCertID),
				})
			}
		}
	}

	privateIDs := map[string]struct{}{}
	for _, row := range privateRows {
		privateIDs[row.ID] = struct{}{}
	}
	for _, row := range privateRows {
		if row.SupersedesCertID != "" {
			if _, ok := privateIDs[row.SupersedesCertID]; !ok {
				findings = append(findings, DoctorFinding{
					Severity: "error",
					Check:    "private_lineage",
					Message:  fmt.Sprintf("private cert %s supersedes missing cert %s", row.ID, row.SupersedesCertID),
				})
			}
		}
	}

	return findings
}

func checkCAInvariants(rootRows []storage.PrivateRootCA, icaRows []storage.PrivateIntermediateCA, now time.Time) []DoctorFinding {
	var findings []DoctorFinding

	rootActive := map[string]int{}
	for _, row := range rootRows {
		if row.Status == storage.StatusActive {
			rootActive[row.Name]++
		}
		if row.IsIssuing && !row.NotAfter.IsZero() && row.NotAfter.Before(now) {
			findings = append(findings, DoctorFinding{
				Severity: "error",
				Check:    "root_expired_issuing",
				Message:  fmt.Sprintf("root CA %s is issuing but expired at %s", row.ID, formatDoctorTime(row.NotAfter)),
			})
		}
		if row.Status != storage.StatusActive && row.IsIssuing {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "root_non_active_issuing",
				Message:  fmt.Sprintf("root CA %s has status %s but is_issuing=true", row.ID, row.Status),
			})
		}
	}
	for name, count := range rootActive {
		if count > 1 {
			findings = append(findings, DoctorFinding{
				Severity: "error",
				Check:    "root_active_count",
				Message:  fmt.Sprintf("root logical name %s has %d active rows", name, count),
			})
		}
	}

	icaActive := map[string]int{}
	rootIDs := map[string]struct{}{}
	for _, row := range rootRows {
		rootIDs[row.ID] = struct{}{}
	}
	for _, row := range icaRows {
		if row.Status == storage.StatusActive {
			icaActive[row.Name]++
		}
		if row.IsIssuing && !row.NotAfter.IsZero() && row.NotAfter.Before(now) {
			findings = append(findings, DoctorFinding{
				Severity: "error",
				Check:    "intermediate_expired_issuing",
				Message:  fmt.Sprintf("intermediate CA %s is issuing but expired at %s", row.ID, formatDoctorTime(row.NotAfter)),
			})
		}
		if row.Status != storage.StatusActive && row.IsIssuing {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "intermediate_non_active_issuing",
				Message:  fmt.Sprintf("intermediate CA %s has status %s but is_issuing=true", row.ID, row.Status),
			})
		}
		if _, ok := rootIDs[row.RootCAID]; !ok {
			findings = append(findings, DoctorFinding{
				Severity: "error",
				Check:    "intermediate_root_ref",
				Message:  fmt.Sprintf("intermediate CA %s references missing root %s", row.ID, row.RootCAID),
			})
		}
	}
	for name, count := range icaActive {
		if count > 1 {
			findings = append(findings, DoctorFinding{
				Severity: "error",
				Check:    "intermediate_active_count",
				Message:  fmt.Sprintf("intermediate logical name %s has %d active rows", name, count),
			})
		}
	}

	return findings
}

func checkPrivateCertIssuers(privateRows []storage.PrivateCert, icaRows []storage.PrivateIntermediateCA) []DoctorFinding {
	var findings []DoctorFinding
	icaByID := map[string]storage.PrivateIntermediateCA{}
	for _, row := range icaRows {
		icaByID[row.ID] = row
	}

	for _, row := range privateRows {
		if row.Status != storage.StatusActive {
			continue
		}
		ica, ok := icaByID[row.IntermediateCAID]
		if !ok {
			findings = append(findings, DoctorFinding{
				Severity: "error",
				Check:    "private_issuer_ref",
				Message:  fmt.Sprintf("private cert %s references missing intermediate %s", row.ID, row.IntermediateCAID),
			})
			continue
		}
		if ica.Status != storage.StatusActive {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "private_inactive_issuer",
				Message:  fmt.Sprintf("active private cert %s is linked to intermediate %s with status %s", row.ID, ica.ID, ica.Status),
			})
		}
		if !strings.Contains(strings.ToLower(row.Issuer), strings.ToLower(ica.CommonName)) && row.Issuer != "" {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "private_issuer_name",
				Message:  fmt.Sprintf("private cert %s issuer %q does not appear to match intermediate %s (%s)", row.ID, row.Issuer, ica.ID, ica.CommonName),
			})
		}
	}

	return findings
}

func checkExpiringLeafs(publicRows []storage.PublicCert, privateRows []storage.PrivateCert, now time.Time, warnWindow time.Duration) []DoctorFinding {
	var findings []DoctorFinding
	for _, row := range publicRows {
		if row.Status != storage.StatusActive || row.NotAfter.IsZero() {
			continue
		}
		if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "public_expiring",
				Message:  fmt.Sprintf("public cert %s (%s) expires in %s at %s", row.ID, row.CommonName, describeRemaining(remaining), formatDoctorTime(row.NotAfter)),
			})
		}
	}
	for _, row := range privateRows {
		if row.Status != storage.StatusActive || row.NotAfter.IsZero() {
			continue
		}
		if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "private_expiring",
				Message:  fmt.Sprintf("private cert %s (%s) expires in %s at %s", row.ID, row.CommonName, describeRemaining(remaining), formatDoctorTime(row.NotAfter)),
			})
		}
	}
	return findings
}

func checkExpiringCAs(rootRows []storage.PrivateRootCA, icaRows []storage.PrivateIntermediateCA, now time.Time, warnWindow time.Duration) []DoctorFinding {
	var findings []DoctorFinding
	for _, row := range rootRows {
		if row.Status != storage.StatusActive || row.NotAfter.IsZero() {
			continue
		}
		if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "root_expiring",
				Message:  fmt.Sprintf("root CA %s (%s) expires in %s at %s", row.ID, row.Name, describeRemaining(remaining), formatDoctorTime(row.NotAfter)),
			})
		}
	}
	for _, row := range icaRows {
		if row.Status != storage.StatusActive || row.NotAfter.IsZero() {
			continue
		}
		if remaining := row.NotAfter.Sub(now); remaining > 0 && remaining <= warnWindow {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "intermediate_expiring",
				Message:  fmt.Sprintf("intermediate CA %s (%s) expires in %s at %s", row.ID, row.Name, describeRemaining(remaining), formatDoctorTime(row.NotAfter)),
			})
		}
	}
	return findings
}

func checkShares(shares []storage.CertShare, now time.Time, warnWindow time.Duration) []DoctorFinding {
	var findings []DoctorFinding
	for _, sh := range shares {
		if !sh.RevokedAt.IsZero() || sh.ExpiresAt.IsZero() {
			continue
		}
		switch remaining := sh.ExpiresAt.Sub(now); {
		case remaining <= 0:
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "share_expired",
				Message:  fmt.Sprintf("share %s for cert %s expired at %s", sh.ID, sh.CertID, formatDoctorTime(sh.ExpiresAt)),
			})
		case remaining <= warnWindow:
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "share_expiring",
				Message:  fmt.Sprintf("share %s for cert %s expires in %s at %s", sh.ID, sh.CertID, describeRemaining(remaining), formatDoctorTime(sh.ExpiresAt)),
			})
		}
	}
	return findings
}

func checkPendingCSRRequests(requests []storage.CSRRequest, now time.Time, warnWindow time.Duration) []DoctorFinding {
	var findings []DoctorFinding
	for _, req := range requests {
		if req.Status != storage.CSRStatusPending || req.CreatedAt.IsZero() {
			continue
		}
		if age := now.Sub(req.CreatedAt); age >= warnWindow {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "csr_pending_age",
				Message:  fmt.Sprintf("pending %s CSR %s (%s) is %s old", req.Kind, req.ID, req.CommonName, describeRemaining(age)),
			})
		}
	}
	return findings
}

func checkAuthIssuerBindings(issuers []storage.AuthIssuer, bindings []storage.AuthzBinding, rules []storage.SubjectAutoApprovalRule) []DoctorFinding {
	var findings []DoctorFinding
	knownIssuers := map[string]storage.AuthIssuer{}
	disabled := map[string]storage.AuthIssuer{}
	referenced := map[string][]string{}
	for _, issuer := range issuers {
		knownIssuers[issuer.Issuer] = issuer
		if !issuer.Enabled {
			disabled[issuer.Issuer] = issuer
		}
	}
	for _, binding := range bindings {
		if !binding.Enabled {
			continue
		}
		for issuerURL := range knownIssuers {
			if bindingReferencesIssuer(binding, issuerURL) {
				referenced[issuerURL] = append(referenced[issuerURL], binding.ID)
				break
			}
		}
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if _, ok := knownIssuers[rule.Issuer]; ok {
			referenced[rule.Issuer] = append(referenced[rule.Issuer], "subject_auto_approval:"+rule.Name)
		}
	}

	for issuerURL, issuer := range disabled {
		bindingIDs := referenced[issuerURL]
		if len(bindingIDs) == 0 {
			continue
		}
		findings = append(findings, DoctorFinding{
			Severity: "warn",
			Check:    "auth_issuer_disabled_reference",
			Message:  fmt.Sprintf("disabled auth issuer %s (%s) is still referenced by enabled bindings: %s", issuer.Name, issuer.Issuer, strings.Join(bindingIDs, ", ")),
		})
	}

	for _, issuer := range issuers {
		if !issuer.Enabled {
			continue
		}
		if len(referenced[issuer.Issuer]) == 0 {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "auth_issuer_unused",
				Message:  fmt.Sprintf("enabled auth issuer %s (%s) has no enabled authz bindings", issuer.Name, issuer.Issuer),
			})
		}
	}

	for _, binding := range bindings {
		issuerURL, ok := bindingPrincipalIssuer(binding.Principal)
		if !ok {
			continue
		}
		if _, exists := knownIssuers[issuerURL]; exists {
			continue
		}
		findings = append(findings, DoctorFinding{
			Severity: "warn",
			Check:    "authz_binding_unknown_issuer",
			Message:  fmt.Sprintf("authz binding %s references unknown issuer %s in principal %s", binding.ID, issuerURL, binding.Principal),
		})
	}

	return findings
}

func checkAuthIssuerDiscovery(issuers []storage.AuthIssuer, bindings []storage.AuthzBinding, probe AuthIssuerProbe) []DoctorFinding {
	if probe == nil {
		return nil
	}

	var findings []DoctorFinding
	for _, issuer := range issuers {
		if !issuer.Enabled {
			continue
		}
		if err := probe(issuer); err != nil {
			var bindingIDs []string
			for _, binding := range bindings {
				if binding.Enabled && bindingReferencesIssuer(binding, issuer.Issuer) {
					bindingIDs = append(bindingIDs, binding.ID)
				}
			}
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "auth_issuer_discovery",
				Message:  fmt.Sprintf("auth issuer %s (%s) discovery or JWKS check failed: %v", issuer.Name, issuer.Issuer, err),
			})
			if len(bindingIDs) > 0 {
				findings = append(findings, DoctorFinding{
					Severity: "warn",
					Check:    "authz_binding_unreachable_issuer",
					Message:  fmt.Sprintf("enabled authz bindings %s reference issuer %s but discovery or JWKS is currently unreachable", strings.Join(bindingIDs, ", "), issuer.Issuer),
				})
			}
		}
	}
	return findings
}

func checkBroadAuthzBindings(bindings []storage.AuthzBinding) []DoctorFinding {
	var findings []DoctorFinding
	for _, binding := range bindings {
		if !binding.Enabled {
			continue
		}
		if strings.TrimSpace(binding.Permission) == "*" {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "authz_binding_wildcard_permission",
				Message:  fmt.Sprintf("authz binding %s grants wildcard permission to %s", binding.ID, binding.Principal),
			})
		}
		if strings.TrimSpace(binding.Principal) == "superuser" {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "authz_binding_superuser",
				Message:  fmt.Sprintf("authz binding %s uses superuser principal", binding.ID),
			})
		}
		if isScopedMutationPermission(binding.Permission) && strings.TrimSpace(binding.ResourceKind) == "" {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "authz_binding_unscoped_mutation",
				Message:  fmt.Sprintf("authz binding %s grants %s without a resource kind scope", binding.ID, binding.Permission),
			})
		}
		if isScopedMutationPermission(binding.Permission) && strings.TrimSpace(binding.ResourceRef) == "*" {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "authz_binding_wildcard_scope",
				Message:  fmt.Sprintf("authz binding %s grants %s with wildcard resource scope", binding.ID, binding.Permission),
			})
		}
	}
	return findings
}

func checkSubjectAutoApprovalRules(issuers []storage.AuthIssuer, rules []storage.SubjectAutoApprovalRule) []DoctorFinding {
	var findings []DoctorFinding
	knownIssuers := map[string]storage.AuthIssuer{}
	for _, issuer := range issuers {
		knownIssuers[issuer.Issuer] = issuer
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		issuer, ok := knownIssuers[rule.Issuer]
		if !ok {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "subject_auto_approval_unknown_issuer",
				Message:  fmt.Sprintf("enabled subject auto approval rule %s references unknown issuer %s", rule.Name, rule.Issuer),
			})
			continue
		}
		if !issuer.Enabled {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "subject_auto_approval_disabled_issuer",
				Message:  fmt.Sprintf("enabled subject auto approval rule %s references disabled issuer %s", rule.Name, rule.Issuer),
			})
		}
		if strings.TrimSpace(rule.EmailDomain) == "" && len(rule.RequiredRoles) == 0 && len(rule.RequiredGroups) == 0 {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "subject_auto_approval_broad",
				Message:  fmt.Sprintf("subject auto approval rule %s auto-activates every subject for issuer %s", rule.Name, rule.Issuer),
			})
		}
	}
	return findings
}

func checkDuplicateAuthzBindings(bindings []storage.AuthzBinding) []DoctorFinding {
	var findings []DoctorFinding
	type bindingKey struct {
		Principal    string
		Permission   string
		ResourceKind string
		ResourceRef  string
	}
	type enableState struct {
		enabledIDs  []string
		disabledIDs []string
	}

	seen := map[bindingKey]*enableState{}
	for _, binding := range bindings {
		key := bindingKey{
			Principal:    strings.TrimSpace(binding.Principal),
			Permission:   strings.TrimSpace(binding.Permission),
			ResourceKind: strings.TrimSpace(binding.ResourceKind),
			ResourceRef:  strings.TrimSpace(binding.ResourceRef),
		}
		state := seen[key]
		if state == nil {
			state = &enableState{}
			seen[key] = state
		}
		if binding.Enabled {
			state.enabledIDs = append(state.enabledIDs, binding.ID)
		} else {
			state.disabledIDs = append(state.disabledIDs, binding.ID)
		}
	}

	for key, state := range seen {
		if len(state.enabledIDs) > 1 {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "authz_binding_duplicate_enabled",
				Message:  fmt.Sprintf("multiple enabled authz bindings share principal=%s permission=%s resource_kind=%s resource_ref=%s: %s", printableScopeValue(key.Principal), printableScopeValue(key.Permission), printableScopeValue(key.ResourceKind), printableScopeValue(key.ResourceRef), strings.Join(state.enabledIDs, ", ")),
			})
		}
		if len(state.enabledIDs) > 0 && len(state.disabledIDs) > 0 {
			findings = append(findings, DoctorFinding{
				Severity: "warn",
				Check:    "authz_binding_conflicting_states",
				Message:  fmt.Sprintf("authz bindings for principal=%s permission=%s resource_kind=%s resource_ref=%s exist in both enabled and disabled states", printableScopeValue(key.Principal), printableScopeValue(key.Permission), printableScopeValue(key.ResourceKind), printableScopeValue(key.ResourceRef)),
			})
		}
	}

	return findings
}

func bindingReferencesIssuer(binding storage.AuthzBinding, issuer string) bool {
	for _, prefix := range []string{"sub:", "role:", "group:"} {
		if strings.HasPrefix(binding.Principal, prefix+issuer+":") {
			return true
		}
	}
	return false
}

func bindingPrincipalIssuer(principal string) (string, bool) {
	for _, prefix := range []string{"sub:", "role:", "group:"} {
		if !strings.HasPrefix(principal, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(principal, prefix)
		if !strings.Contains(remainder, "://") {
			return "", false
		}
		idx := strings.LastIndex(remainder, ":")
		if idx <= 0 || idx == len(remainder)-1 {
			return "", false
		}
		issuer := strings.TrimSpace(remainder[:idx])
		if issuer == "" {
			return "", false
		}
		return issuer, true
	}
	return "", false
}

func isScopedMutationPermission(permission string) bool {
	switch strings.TrimSpace(permission) {
	case "csr.approve", "csr.reject", "csr.submit":
		return true
	default:
		return false
	}
}

func printableScopeValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "<empty>"
	}
	return value
}

func describeRemaining(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int(d.Round(24*time.Hour) / (24 * time.Hour))
	if days <= 0 {
		return "less than 1 day"
	}
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}

func formatDoctorTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

var _ = sql.ErrNoRows
