package util

import (
	"fmt"
	"strings"
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
