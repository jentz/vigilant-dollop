package crypto

import (
	"testing"
)

func TestPkceCodeVerifier(t *testing.T) {
	var tests = []struct {
		name          string
		generateBytes int
		wantBytes     int
		wantPanic     bool
	}{
		{"24 bytes random, string too short", 24, 32, true},
		{"32 bytes random, 43 bytes string", 32, 43, false},
		{"64 bytes random, 86 bytes string", 64, 86, false},
		{"96 bytes random, 128 bytes string", 96, 128, false},
		{"128 bytes random, string too long", 128, 152, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if (r != nil) != tt.wantPanic {
					t.Errorf("pkceCodeVerifier() recover = %v, wantPanic = %v", r, tt.wantPanic)
				}
			}()
			gotBytes := len(CreatePkceCodeVerifier(tt.generateBytes))
			if gotBytes != tt.wantBytes {
				t.Errorf("err got %v, want %v", gotBytes, tt.wantBytes)
			}
		})
	}
}
