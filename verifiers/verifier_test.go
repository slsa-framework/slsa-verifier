package verifiers

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
)

func Test_ensureCompleteClientOpts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts *[]options.ClientOpts
		err  error
	}{
		{
			name: "success: no ClientOpts",
			opts: &[]options.ClientOpts{},
			err:  nil,
		},
		{
			name: "success: one ClientOpt",
			opts: &[]options.ClientOpts{
				{},
			},
			err: nil,
		},
		{
			name: "failure: multiple ClientOpts",
			opts: &[]options.ClientOpts{
				{},
				{},
			},
			err: serrors.ErrorInvalidClientOpts,
		},
	}

	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts, err := ensureCompleteClientOpts(*tt.opts...)
			if errorDiff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); errorDiff != "" {
				t.Errorf("unexpected error (-want +got):\n%s", errorDiff)
			}

			if err != nil && opts != nil {
				t.Errorf("expected opts to be non-nil")
			}

			if err == nil && opts == nil {
				t.Errorf("expected opts to be nil")
			}
		})
	}
}
