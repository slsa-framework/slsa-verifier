package v10

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/common"
)

func Test_getSubstitutionsField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		field string
		path  string
		value string
		err   error
	}{
		{
			name:  "v1.0 match branch",
			path:  "./testdata/internalParameters.json",
			field: "BRANCH_NAME",
			value: "main",
		},
		{
			name:  "v1.0 tag not present",
			path:  "./testdata/internalParameters.json",
			field: "TAG_NAME",
			err:   common.ErrSubstitution,
		},
		{
			name:  "v1.0 match repo name",
			path:  "./testdata/internalParameters.json",
			field: "REPO_NAME",
			value: "gcb-prod-prov",
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

			var internalParemeters map[string]any
			err = json.Unmarshal(content, &internalParemeters)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			value, err := getSubstitutionsField(internalParemeters, tt.field)
			if !cmp.Equal(err, tt.err, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
			}
			if err == nil && !cmp.Equal(value, tt.value) {
				t.Errorf(cmp.Diff(value, tt.value))
			}
		})
	}
}
