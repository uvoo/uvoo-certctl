package util

import (
	"fmt"
	"strings"
	"unicode"
)

func ResolveCryptoPassword(keyPassword, storagePassword string) (string, error) {
	if strings.TrimSpace(keyPassword) != "" {
		return keyPassword, nil
	}
	if strings.TrimSpace(storagePassword) != "" {
		return storagePassword, nil
	}
	return "", fmt.Errorf("either --key-password or --storage-password is required")
}

func IsPasswordComplex(pass string) error {
	if len(pass) < 12 {
		return fmt.Errorf("must be at least 12 characters")
	}
	var upper, lower, number, special bool
	for _, r := range pass {
		switch {
		case unicode.IsUpper(r): upper = true
		case unicode.IsLower(r): lower = true
		case unicode.IsDigit(r): number = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r): special = true
		}
	}
	if !upper { return fmt.Errorf("must include uppercase") }
	if !lower { return fmt.Errorf("must include lowercase") }
	if !number { return fmt.Errorf("must include number") }
	if !special { return fmt.Errorf("must include special character") }
	return nil
}
