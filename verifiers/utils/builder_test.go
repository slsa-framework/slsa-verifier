package utils

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
)

func Test_ParseBuilderID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		builderID      string
		needVersion    bool
		builderName    string
		builderVersion string
		err            error
	}{
		{
			name:           "valid builder with version - need version",
			builderID:      "some/name@v1.2.3",
			needVersion:    true,
			builderName:    "some/name",
			builderVersion: "v1.2.3",
		},
		{
			name:           "valid builder with version - no need version",
			builderID:      "some/name@v1.2.3",
			builderName:    "some/name",
			builderVersion: "v1.2.3",
		},
		{
			name:        "valid builder without version - no need version",
			builderID:   "some/name",
			builderName: "some/name",
		},
		{
			name:        "no version ID - need version",
			needVersion: true,
			err:         serrors.ErrorInvalidFormat,
		},
		{
			name:        "too many '@' - need version",
			builderID:   "some/name@vla@blo",
			needVersion: true,
			err:         serrors.ErrorInvalidFormat,
		},
		{
			name:      "too many '@' - no need version",
			builderID: "some/name@vla@blo",
			err:       serrors.ErrorInvalidFormat,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			name, version, err := ParseBuilderID(tt.builderID, tt.needVersion)
			if !cmp.Equal(err, tt.err, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.err))
			}

			if err != nil {
				return
			}

			if name != tt.builderName {
				t.Errorf(cmp.Diff(name, tt.builderName))
			}

			if version != tt.builderVersion {
				t.Errorf(cmp.Diff(version, tt.builderVersion))
			}
		})
	}
}

func Test_BuilderIDNew(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		builderID      string
		builderName    string
		builderVersion string
		err            error
	}{
		{
			name:           "valid",
			builderID:      "some/name@v1.2.3",
			builderName:    "some/name",
			builderVersion: "v1.2.3",
		},
		{
			name:      "too many '@' - need version",
			builderID: "some/name@vla@blo",
			err:       serrors.ErrorInvalidFormat,
		},
		{
			name:      "too many '@' - no need version",
			builderID: "some/name@vla@blo",
			err:       serrors.ErrorInvalidFormat,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			builderID, err := BuilderIDNew(tt.builderID)
			if !cmp.Equal(err, tt.err, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.err))
			}

			if err != nil {
				return
			}

			name := builderID.Name()
			version := builderID.Version()
			full := builderID.String()

			if name != tt.builderName {
				t.Errorf(cmp.Diff(tt.builderName, name))
			}
			if version != tt.builderVersion {
				t.Errorf(cmp.Diff(tt.builderVersion, version))
			}
			if full != tt.builderID {
				t.Errorf(cmp.Diff(tt.builderID, full))
			}
		})
	}
}

func Test_Matches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		builderID string
		match     string
		err       error
	}{
		{
			name:      "match full",
			builderID: "some/name@v1.2.3",
			match:     "some/name@v1.2.3",
		},
		{
			name:      "match name",
			builderID: "some/name@v1.2.3",
			match:     "some/name",
		},
		{
			name:      "mismatch name",
			builderID: "some/name@v1.2.3",
			match:     "some/name2",
			err:       serrors.ErrorMismatchBuilderID,
		},
		{
			name:      "mismatch version",
			builderID: "some/name@v1.2.3",
			match:     "some/name@v1.2.4",
			err:       serrors.ErrorMismatchBuilderID,
		},
		{
			name:      "too many '@' - need version",
			builderID: "some/name@v1.2.3",
			match:     "some/name@vla@blo",
			err:       serrors.ErrorInvalidFormat,
		},
		{
			name:      "too many '@' - no need version",
			builderID: "some/name@v1.2.3",
			match:     "some/name@vla@blo",
			err:       serrors.ErrorInvalidFormat,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			builderID, err := BuilderIDNew(tt.builderID)
			if err != nil {
				panic(fmt.Errorf("BuilderIDNew: %w", err))
			}

			err = builderID.Matches(tt.match)
			if !cmp.Equal(err, tt.err, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}
