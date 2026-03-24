package util

import (
	"fmt"
	"os"
	"strings"
)

func FirstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func EnvOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func Require(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("missing required value: %s", name)
	}
	return nil
}
