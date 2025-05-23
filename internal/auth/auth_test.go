package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		name    string
		input   http.Header
		want    string
		wantErr error
	}

	tests := []test{
		{
			name:    "Valid ApiKey Token",
			input:   http.Header{"Authorization": {"ApiKey ValidAPIKeyString"}},
			want:    "ValidAPIKeyString",
			wantErr: nil,
		},
		{
			name:    "Missing Authorization Header",
			input:   http.Header{}, // Empty header
			want:    "",
			wantErr: nil, //ErrNoAuthHeaderIncluded, // Use the specific error variable
		},
		{
			name:    "Empty Authorization Header Value",
			input:   http.Header{"Authorization": {""}},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded, // Or a specific empty value error
		},
		{
			name:    "Malformed Header (Missing Space)",
			input:   http.Header{"Authorization": {"ApiKeyValidAPIKeyString"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "Malformed Header (Just Scheme)",
			input:   http.Header{"Authorization": {"ApiKey"}}, // No key part
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.input)

			// Check for expected error
			if (err != nil) != (tt.wantErr != nil) {
				t.Fatalf("Test '%s': unexpected error status. Expected error: %v, Got error: %v", tt.name, tt.wantErr, err)
			}
			if err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				// Compare error messages if both are expected (adjust if comparing error types instead)
				t.Errorf("Test '%s': unexpected error message.\nExpected: %v\nGot:      %v", tt.name, tt.wantErr.Error(), err.Error())
			}

			// Check for expected successful result
			if got != tt.want {
				t.Errorf("Test '%s': unexpected result.\nExpected: %v\nGot:      %v", tt.name, tt.want, got)
			}
		})
	}

}
