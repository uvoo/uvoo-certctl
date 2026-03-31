package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"certctl/internal/storage"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

var (
	ErrMissingBearerToken = errors.New("missing bearer token")
	ErrInvalidToken       = errors.New("invalid bearer token")
	ErrForbidden          = errors.New("forbidden")
)

type Verifier struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]issuerState
}

type IssuerCheckResult struct {
	DiscoveryURL string
	JWKSURL      string
	KeyCount     int
}

type TokenInspection struct {
	Issuer    string
	Subject   string
	Audiences []string
	RawClaims map[string]any
}

type issuerState struct {
	jwksURL   string
	keys      jose.JSONWebKeySet
	fetchedAt time.Time
}

type discoveryDocument struct {
	JWKSURI string `json:"jwks_uri"`
}

func NewVerifier(timeout time.Duration) *Verifier {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return NewVerifierWithClient(&http.Client{Timeout: timeout})
}

func NewVerifierWithClient(client *http.Client) *Verifier {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{
		client: client,
		cache:  map[string]issuerState{},
	}
}

func CheckIssuerConnectivity(ctx context.Context, client *http.Client, issuer storage.AuthIssuer) error {
	return NewVerifierWithClient(client).checkIssuerConnectivity(ctx, issuer)
}

func (v *Verifier) CheckIssuerConnectivity(ctx context.Context, issuer storage.AuthIssuer) error {
	return v.checkIssuerConnectivity(ctx, issuer)
}

func (v *Verifier) CheckIssuer(ctx context.Context, issuer storage.AuthIssuer) (IssuerCheckResult, error) {
	discoveryURL := strings.TrimSpace(issuer.DiscoveryURL)
	if discoveryURL == "" {
		discoveryURL = strings.TrimRight(strings.TrimSpace(issuer.Issuer), "/") + "/.well-known/openid-configuration"
	}
	keys, err := v.keysForIssuer(ctx, issuer, true)
	if err != nil {
		return IssuerCheckResult{DiscoveryURL: discoveryURL}, err
	}

	v.mu.Lock()
	state := v.cache[issuer.Issuer]
	v.mu.Unlock()
	return IssuerCheckResult{
		DiscoveryURL: discoveryURL,
		JWKSURL:      state.jwksURL,
		KeyCount:     len(keys),
	}, nil
}

func InspectToken(token string) (TokenInspection, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return TokenInspection{}, ErrMissingBearerToken
	}

	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
	})
	if err != nil {
		return TokenInspection{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	var rawClaims map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&rawClaims); err != nil {
		return TokenInspection{}, fmt.Errorf("%w: unable to inspect token claims", ErrInvalidToken)
	}
	issuer, _ := claimString(rawClaims, "iss")
	subject, _ := claimString(rawClaims, "sub")
	return TokenInspection{
		Issuer:    issuer,
		Subject:   subject,
		Audiences: collectClaimValues(rawClaims, []string{"aud"}),
		RawClaims: rawClaims,
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, token string, issuers []storage.AuthIssuer) (Identity, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Identity{}, ErrMissingBearerToken
	}

	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
	})
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	var rawClaims map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&rawClaims); err != nil {
		return Identity{}, fmt.Errorf("%w: unable to inspect token claims", ErrInvalidToken)
	}
	tokenIssuer, _ := claimString(rawClaims, "iss")
	if tokenIssuer == "" {
		return Identity{}, fmt.Errorf("%w: missing iss claim", ErrInvalidToken)
	}

	var lastErr error
	for _, issuer := range issuers {
		if !issuer.Enabled || strings.TrimSpace(issuer.Issuer) != tokenIssuer {
			continue
		}
		identity, err := v.verifyAgainstIssuer(ctx, parsed, rawClaims, issuer)
		if err == nil {
			return identity, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrInvalidToken, lastErr)
	}
	return Identity{}, fmt.Errorf("%w: untrusted issuer", ErrInvalidToken)
}

func (v *Verifier) verifyAgainstIssuer(ctx context.Context, parsed *josejwt.JSONWebToken, rawClaims map[string]any, issuer storage.AuthIssuer) (Identity, error) {
	keys, err := v.keysForIssuer(ctx, issuer, false)
	if err != nil {
		return Identity{}, err
	}

	headerKid := ""
	if len(parsed.Headers) > 0 {
		headerKid = strings.TrimSpace(parsed.Headers[0].KeyID)
	}

	if identity, err := verifyWithKeys(parsed, rawClaims, issuer, selectKeys(keys, headerKid)); err == nil {
		return identity, nil
	}

	keys, err = v.keysForIssuer(ctx, issuer, true)
	if err != nil {
		return Identity{}, err
	}
	return verifyWithKeys(parsed, rawClaims, issuer, selectKeys(keys, headerKid))
}

func (v *Verifier) checkIssuerConnectivity(ctx context.Context, issuer storage.AuthIssuer) error {
	_, err := v.keysForIssuer(ctx, issuer, true)
	return err
}

func verifyWithKeys(parsed *josejwt.JSONWebToken, rawClaims map[string]any, issuer storage.AuthIssuer, keys []jose.JSONWebKey) (Identity, error) {
	if len(keys) == 0 {
		return Identity{}, errors.New("no jwks keys available")
	}

	for _, key := range keys {
		var std josejwt.Claims
		var verified map[string]any
		if err := parsed.Claims(key.Key, &std, &verified); err != nil {
			continue
		}
		expected := josejwt.Expected{
			Issuer: issuer.Issuer,
			Time:   time.Now().UTC(),
		}
		if len(issuer.Audiences) > 0 {
			expected.AnyAudience = josejwt.Audience(issuer.Audiences)
		}
		if err := std.ValidateWithLeeway(expected, time.Minute); err != nil {
			continue
		}
		if err := validateRequiredClaims(verified, issuer.RequiredClaims); err != nil {
			return Identity{}, err
		}

		subject := firstNonEmpty(
			claimPathString(verified, issuer.SubjectClaim),
			std.Subject,
		)
		if subject == "" {
			return Identity{}, errors.New("missing subject claim")
		}

		username := claimPathString(verified, issuer.UsernameClaim)
		email := claimPathString(verified, issuer.EmailClaim)
		roles := uniqueStrings(collectClaimValues(verified, issuer.RolesClaims)...)
		groups := uniqueStrings(collectClaimValues(verified, issuer.GroupsClaims)...)

		return Identity{
			AuthMethod: "bearer",
			Issuer:     issuer.Issuer,
			Subject:    subject,
			Username:   username,
			Email:      email,
			Roles:      roles,
			Groups:     groups,
			Principals: principalsFor(issuer.Issuer, subject, roles, groups),
			RawClaims:  verified,
		}, nil
	}

	return Identity{}, errors.New("signature verification failed")
}

func (v *Verifier) keysForIssuer(ctx context.Context, issuer storage.AuthIssuer, forceRefresh bool) ([]jose.JSONWebKey, error) {
	v.mu.Lock()
	state, ok := v.cache[issuer.Issuer]
	if ok && !forceRefresh && time.Since(state.fetchedAt) < 15*time.Minute && len(state.keys.Keys) > 0 {
		keys := append([]jose.JSONWebKey(nil), state.keys.Keys...)
		v.mu.Unlock()
		return keys, nil
	}
	v.mu.Unlock()

	jwksURL, err := v.resolveJWKSURL(ctx, issuer, state.jwksURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch failed with status %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	if len(jwks.Keys) == 0 {
		return nil, errors.New("jwks returned no keys")
	}

	v.mu.Lock()
	v.cache[issuer.Issuer] = issuerState{
		jwksURL:   jwksURL,
		keys:      jwks,
		fetchedAt: time.Now().UTC(),
	}
	v.mu.Unlock()

	return append([]jose.JSONWebKey(nil), jwks.Keys...), nil
}

func (v *Verifier) resolveJWKSURL(ctx context.Context, issuer storage.AuthIssuer, cached string) (string, error) {
	if strings.TrimSpace(issuer.JWKSURL) != "" {
		return strings.TrimSpace(issuer.JWKSURL), nil
	}
	if strings.TrimSpace(cached) != "" {
		return strings.TrimSpace(cached), nil
	}

	discoveryURL := strings.TrimSpace(issuer.DiscoveryURL)
	if discoveryURL == "" {
		discoveryURL = strings.TrimRight(strings.TrimSpace(issuer.Issuer), "/") + "/.well-known/openid-configuration"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc discovery failed with status %d", resp.StatusCode)
	}

	var doc discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", err
	}
	if strings.TrimSpace(doc.JWKSURI) == "" {
		return "", errors.New("oidc discovery missing jwks_uri")
	}
	return doc.JWKSURI, nil
}

func selectKeys(keys []jose.JSONWebKey, keyID string) []jose.JSONWebKey {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return keys
	}
	out := make([]jose.JSONWebKey, 0, len(keys))
	for _, key := range keys {
		if strings.TrimSpace(key.KeyID) == keyID {
			out = append(out, key)
		}
	}
	if len(out) == 0 {
		return keys
	}
	return out
}

func principalsFor(issuer, subject string, roles, groups []string) []string {
	principals := []string{
		fmt.Sprintf("sub:%s:%s", issuer, subject),
	}
	for _, role := range roles {
		principals = append(principals, fmt.Sprintf("role:%s:%s", issuer, role))
	}
	for _, group := range groups {
		principals = append(principals, fmt.Sprintf("group:%s:%s", issuer, group))
	}
	return uniqueStrings(principals...)
}

func claimString(claims map[string]any, key string) (string, bool) {
	value, ok := claims[key]
	if !ok {
		return "", false
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed), strings.TrimSpace(typed) != ""
	default:
		return "", false
	}
}

func claimPathString(claims map[string]any, path string) string {
	value := claimPathValue(claims, path)
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	default:
		return ""
	}
}

func collectClaimValues(claims map[string]any, paths []string) []string {
	var out []string
	for _, path := range paths {
		value := claimPathValue(claims, path)
		switch typed := value.(type) {
		case string:
			if v := strings.TrimSpace(typed); v != "" {
				out = append(out, v)
			}
		case bool:
			out = append(out, claimPathString(map[string]any{"value": typed}, "value"))
		case float64:
			out = append(out, claimPathString(map[string]any{"value": typed}, "value"))
		case []any:
			for _, item := range typed {
				if v, ok := item.(string); ok && strings.TrimSpace(v) != "" {
					out = append(out, strings.TrimSpace(v))
				}
			}
		case []string:
			for _, item := range typed {
				if v := strings.TrimSpace(item); v != "" {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

func claimPathValue(claims map[string]any, path string) any {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	current := any(claims)
	for _, part := range strings.Split(path, ".") {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = obj[part]
		if !ok {
			return nil
		}
	}
	return current
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func uniqueStrings(values ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
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

func validateRequiredClaims(claims map[string]any, required map[string]string) error {
	for path, expected := range required {
		if claimPathString(claims, path) != strings.TrimSpace(expected) {
			return fmt.Errorf("required claim %s=%q not satisfied", path, expected)
		}
	}
	return nil
}
