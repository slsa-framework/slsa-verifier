package v01

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/common"
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}
			fmt.Println(string(content))
			_, err = New(content)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Error(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_getSubstitutionsField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		path  string
		field string
		value string
		err   error
	}{
		{
			name:  "match tag",
			path:  "./testdata/substitution.json",
			field: "TAG_NAME",
			value: "v33.0.4",
		},
		{
			name:  "match repo name",
			path:  "./testdata/substitution.json",
			field: "REPO_NAME",
			value: "gcb-tests",
		},
		{
			name:  "tag not present",
			path:  "./testdata/substitution.json",
			field: "DOES_NOT_EXIST",
			err:   common.ErrSubstitution,
		},
		{
			name:  "tag not string",
			path:  "./testdata/substitution-int.json",
			field: "TAG_NAME",
			err:   common.ErrSubstitution,
		},
	}
	for _, tt := range tests {
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
				t.Error(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
			}
			if err == nil && !cmp.Equal(value, tt.value) {
				t.Error(cmp.Diff(value, tt.value))
			}
		})
	}
}
