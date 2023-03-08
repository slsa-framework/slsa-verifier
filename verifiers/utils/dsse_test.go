package utils

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func Test_DecodeSignature(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		encoded  string
		decoded  string
		expected error
	}{
		{
			name:    "std encoding",
			encoded: "YWJjMTIzIT8kKiYoKSctPUB+",
			decoded: "abc123!?$*&()'-=@~",
		},
		{
			name:    "URL encoding",
			encoded: "YWJjMTIzIT8kKiYoKSctPUB-",
			decoded: "abc123!?$*&()'-=@~",
		},
		{
			name:     "invalid",
			encoded:  "invalid encoding",
			expected: serrors.ErrorInvalidEncoding,
		},
	}

	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, err := DecodeSignature(tt.encoded)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
			if err != nil {
				return
			}
			cs := string(c)
			if cs != tt.decoded {
				t.Errorf(cmp.Diff(cs, tt.decoded))
			}
		})
	}
}
