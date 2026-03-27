package util

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

func NormalizeDomain(domain string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func BaseLookupDomain(domain string) string {
	return strings.TrimPrefix(NormalizeDomain(domain), "*.")
}

func RootZone(domain string) (string, error) {
	d := BaseLookupDomain(domain)
	if d == "" {
		return "", fmt.Errorf("domain is empty")
	}
	zone, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return "", fmt.Errorf("derive zone for %q: %w", domain, err)
	}
	return zone, nil
}

func RelativeRecordName(zone, fqdnOrLabel string) string {
	zone = NormalizeDomain(zone)
	name := NormalizeDomain(fqdnOrLabel)
	if name == zone || name == "@" || name == "" {
		return "@"
	}
	if before, ok := strings.CutSuffix(name, "."+zone); ok {
		trimmed := before
		if trimmed == "" {
			return "@"
		}
		return trimmed
	}
	return name
}

func ACMEChallengeFQDN(domain string) string {
	base := BaseLookupDomain(domain)
	return "_acme-challenge." + base
}
