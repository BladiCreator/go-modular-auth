package phone

import (
	"testing"
)

func TestDefaultNormalizer(t *testing.T) {
	norm := DefaultNormalizer()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "Standard US E.164",
			input:   "+12025550123",
			want:    "+12025550123",
			wantErr: false,
		},
		{
			name:    "Formatted US number with spaces and parens",
			input:   "+1 (202) 555-0123",
			want:    "+12025550123",
			wantErr: false,
		},
		{
			name:    "International dial prefix 00",
			input:   "0044 20 7183 8750",
			want:    "+442071838750",
			wantErr: false,
		},
		{
			name:    "Spanish mobile number with dots",
			input:   "+34.612.345.678",
			want:    "+34612345678",
			wantErr: false,
		},
		{
			name:    "Without leading plus (auto prepended)",
			input:   "12025550123",
			want:    "+12025550123",
			wantErr: false,
		},
		{
			name:    "Empty input",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "Too short",
			input:   "+12345",
			wantErr: true,
		},
		{
			name:    "Too long (exceeds 15 digits)",
			input:   "+12345678901234567",
			wantErr: true,
		},
		{
			name:    "Contains letters",
			input:   "+1202555012A",
			wantErr: true,
		},
		{
			name:    "Leading zero after plus (invalid country code)",
			input:   "+0123456789",
			wantErr: true,
		},
		{
			name:    "Plus inside number",
			input:   "1202+5550123",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := norm(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil (got %q)", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("for %q: got %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestDefaultValidator(t *testing.T) {
	val := DefaultValidator()

	if err := val("+12025550123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := val("12025550123"); err == nil {
		t.Fatal("expected error for missing plus")
	}
	if err := val("+12345"); err == nil {
		t.Fatal("expected error for too short")
	}
}

func FuzzNormalizeE164(f *testing.F) {
	seeds := []string{
		"+12025550123",
		"+1 (202) 555-0123",
		"0044 20 7183 8750",
		"+34.612.345.678",
		"12025550123",
		"",
		"   ",
		"+0123456789",
		"+12345678901234567890",
		"+1202555012A",
		"📞+1-800-GO-FED",
		"\x00\xff\xfe",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	norm := DefaultNormalizer()
	val := DefaultValidator()

	f.Fuzz(func(t *testing.T, input string) {
		res, err := norm(input)
		if err != nil {
			return
		}
		// If normalization succeeds, it must pass E.164 validation without error!
		if err := val(res); err != nil {
			t.Fatalf("normalized output %q failed validation: %v", res, err)
		}
	})
}

