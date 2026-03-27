package util

import (
	"strconv"
	"strings"
	"time"
	"github.com/google/uuid"
)

func NewID() string {
    return uuid.NewString()
}

func ParseFlexibleDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
