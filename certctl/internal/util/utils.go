package util

import (
	"github.com/google/uuid"
	"strconv"
	"strings"
	"time"
)

func NewID() string {
	return uuid.NewString()
}

func ParseFlexibleDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if before, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(before)
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
