package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

func ResolveCryptoPassword(keyPassword, storagePassword string) (string, error) {
	keyResolved, err := ResolveSecretValue(keyPassword, "CERTCTL_KEY_PASSWORD")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(keyResolved) != "" {
		return keyResolved, nil
	}
	storageResolved, err := ResolveSecretValue(storagePassword, "CERTCTL_STORAGE_PASSWORD")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(storageResolved) != "" {
		return storageResolved, nil
	}
	return "", fmt.Errorf("either --key-password or --storage-password is required")
}

func ResolveSecretValue(value string, fallbackEnv ...string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		for _, key := range fallbackEnv {
			if v := strings.TrimSpace(os.Getenv(key)); v != "" {
				return v, nil
			}
		}
		return "", nil
	}

	if name, ok := strings.CutPrefix(value, "env:"); ok {
		name = strings.TrimSpace(name)
		if name == "" {
			return "", fmt.Errorf("empty env name in secret reference")
		}
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("environment variable %s is empty", name)
	}

	if filePath, ok := strings.CutPrefix(value, "file:"); ok {
		filePath = strings.TrimSpace(filePath)
		if filePath == "" {
			return "", fmt.Errorf("empty file path in secret reference")
		}
		data, err := os.ReadFile(filepath.Clean(filePath))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}

	return value, nil
}

func IsPasswordComplex(pass string) error {
	if len(pass) < 12 {
		return fmt.Errorf("must be at least 12 characters")
	}
	var upper, lower, number, special bool
	for _, r := range pass {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			number = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			special = true
		}
	}
	if !upper {
		return fmt.Errorf("must include uppercase")
	}
	if !lower {
		return fmt.Errorf("must include lowercase")
	}
	if !number {
		return fmt.Errorf("must include number")
	}
	if !special {
		return fmt.Errorf("must include special character")
	}
	return nil
}
