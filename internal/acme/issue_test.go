package acme

import (
	"reflect"
	"testing"
)

func TestResolverList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty",
			input:    " ",
			expected: nil,
		},
		{
			name:     "single",
			input:    "8.8.8.8",
			expected: []string{"8.8.8.8"},
		},
		{
			name:     "comma separated",
			input:    "8.8.8.8, 1.1.1.1",
			expected: []string{"8.8.8.8", "1.1.1.1"},
		},
		{
			name:     "skips blanks",
			input:    "8.8.8.8,, 1.1.1.1, ",
			expected: []string{"8.8.8.8", "1.1.1.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolverList(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("resolverList(%q) = %#v, want %#v", tt.input, got, tt.expected)
			}
		})
	}
}
