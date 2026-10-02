package reserved

import "testing"

func TestName(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"api", true},
		{"ui", true},
		{"auth", true},
		{"healthz", true},
		{"readyz", true},
		// Only exact names are reserved: the router matches whole segments.
		{"apifoo", false},
		{"uix", false},
		{"API", false},
		{"photos", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := Name(tc.input); got != tc.want {
			t.Errorf("Name(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
