package v01

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func Test_New(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		expected error
	}{
		{
			name: "valid gcb provenance",
			path: "./testdata/gcloud-container-github.json",
		},
		{
			name: "valid gcb provenance gcs",
			path: "./testdata/gcloud-container-gcs.json",
		},
		{
			name:     "invalid intoto header",
			path:     "./testdata/gcloud-container-invalid-intotoheader.json",
			expected: serrors.ErrorInvalidDssePayload,
		},
		{
			name:     "invalid provenance header",
			path:     "./testdata/gcloud-container-invalid-slsaheader.json",
			expected: serrors.ErrorInvalidDssePayload,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}
			fmt.Println(string(content))
			_, err = New(content)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}
