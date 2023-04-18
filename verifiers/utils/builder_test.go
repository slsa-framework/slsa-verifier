package utils

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
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
		{
			name:        "empty version - need version",
			builderID:   "some/name@",
			needVersion: true,
			err:         serrors.ErrorInvalidFormat,
		},
		{
			name:      "empty version - no need version",
			builderID: "some/name@",
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
		name             string
		trustedBuilderID string
		needVersion      bool
		builderName      string
		builderVersion   string
		err              error
	}{
		{
			name:             "valid with version",
			trustedBuilderID: "some/name@v1.2.3",
			builderName:      "some/name",
			builderVersion:   "v1.2.3",
			needVersion:      true,
		},
		{
			name:             "invalid without version",
			trustedBuilderID: "some/name",
			builderName:      "some/name",
			needVersion:      true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "valid without version",
			trustedBuilderID: "some/name",
			builderName:      "some/name",
			needVersion:      false,
		},
		{
			name:             "empty version",
			trustedBuilderID: "some/name@",
			needVersion:      true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - need version",
			trustedBuilderID: "some/name@vla@blo",
			needVersion:      true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - no need version",
			trustedBuilderID: "some/name@vla@blo",
			needVersion:      true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "valid",
			trustedBuilderID: "some/name@v1.2.3",
			builderName:      "some/name",
			builderVersion:   "v1.2.3",
			needVersion:      false,
		},
		{
			name:             "empty version",
			trustedBuilderID: "some/name@",
			needVersion:      false,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - need version",
			trustedBuilderID: "some/name@vla@blo",
			needVersion:      false,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - no need version",
			trustedBuilderID: "some/name@vla@blo",
			needVersion:      false,
			err:              serrors.ErrorInvalidFormat,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			trustedBuilderID, err := TrustedBuilderIDNew(tt.trustedBuilderID, tt.needVersion)
			if !cmp.Equal(err, tt.err, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.err))
			}

			if err != nil {
				return
			}

			name := trustedBuilderID.Name()
			version := trustedBuilderID.Version()
			full := trustedBuilderID.String()

			if name != tt.builderName {
				t.Errorf(cmp.Diff(tt.builderName, name))
			}
			if version != tt.builderVersion {
				t.Errorf(cmp.Diff(tt.builderVersion, version))
			}
			if full != tt.trustedBuilderID {
				t.Errorf(cmp.Diff(tt.trustedBuilderID, full))
			}
		})
	}
}

func Test_MatchesLoose(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		trustedBuilderID string
		needVersion      bool
		allowRef         bool
		match            string
		err              error
	}{
		{
			name:             "match full need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@v1.2.3",
			needVersion:      true,
		},
		{
			name:             "match full with ref",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "match full no need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@v1.2.3",
		},
		{
			name:             "match name no need version",
			trustedBuilderID: "some/name",
			match:            "some/name@v1.2.3",
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "match name",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name",
			needVersion:      true,
		},
		{
			name:             "mismatch name",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name2",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "mismatch version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@v1.2.4",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "invalid empty version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@",
			needVersion:      true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@vla@blo",
			needVersion:      true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - no need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@vla@blo",
			needVersion:      true,
			err:              serrors.ErrorInvalidFormat,
		},
		// Same as above with `allowRef: true`.
		{
			name:             "match full",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@v1.2.3",
			needVersion:      true,
			allowRef:         true,
		},
		{
			name:             "match full no need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@v1.2.3",
			allowRef:         true,
		},
		{
			name:             "match name no need version",
			trustedBuilderID: "some/name",
			match:            "some/name@v1.2.3",
			allowRef:         true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "match name",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name",
			needVersion:      true,
			allowRef:         true,
		},
		{
			name:             "match name",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name",
			needVersion:      true,
			allowRef:         true,
		},
		{
			name:             "mismatch name",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name2",
			needVersion:      true,
			allowRef:         true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "mismatch version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@v1.2.4",
			needVersion:      true,
			allowRef:         true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "invalid empty version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@",
			needVersion:      true,
			allowRef:         true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@vla@blo",
			needVersion:      true,
			allowRef:         true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - no need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@vla@blo",
			needVersion:      true,
			allowRef:         true,
			err:              serrors.ErrorInvalidFormat,
		},
		// Mismatch of tag length.
		{
			name:             "match long tag match short",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			needVersion:      true,
			allowRef:         true,
		},
		{
			name:             "long tag match short no ref",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "match long tags",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@refs/tags/v1.2.3",
			needVersion:      true,
			allowRef:         true,
		},
		{
			name:             "mismatch tag length",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "mismatch tag length inversed",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@refs/tags/v1.2.3",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		// mismatch tag length no need version
		{
			name:             "match long tag match short",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			allowRef:         true,
		},
		{
			name:             "long tag match short no ref",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "match long tags",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@refs/tags/v1.2.3",
			allowRef:         true,
		},
		{
			name:             "mismatch tag length",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "mismatch tag length inversed",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@refs/tags/v1.2.3",
			err:              serrors.ErrorMismatchBuilderID,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			trustedBuilderID, err := TrustedBuilderIDNew(tt.trustedBuilderID, tt.needVersion)
			if err != nil {
				panic(fmt.Errorf("BuilderIDNew: %w", err))
			}

			err = trustedBuilderID.MatchesLoose(tt.match, tt.allowRef)
			if !cmp.Equal(err, tt.err, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_MatchesFull(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		trustedBuilderID string
		needVersion      bool
		allowRef         bool
		match            string
		err              error
	}{
		{
			name:             "match full",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@v1.2.3",
			needVersion:      true,
		},
		{
			name:             "match name no need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name",
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "match name full no need version",
			trustedBuilderID: "some/name",
			match:            "some/name",
		},
		{
			name:             "match full no need version",
			trustedBuilderID: "some/name",
			match:            "some/name@v1.2.3",
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "match name",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "mismatch name",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name2",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "mismatch version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@v1.2.4",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "invalid empty version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@",
			needVersion:      true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@vla@blo",
			needVersion:      true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - no need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@vla@blo",
			needVersion:      true,
			err:              serrors.ErrorInvalidFormat,
		},
		// Same as above with `allowRef: true`.
		{
			name:             "match full",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@v1.2.3",
			needVersion:      true,
			allowRef:         true,
		},
		{
			name:             "match name",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name",
			needVersion:      true,
			allowRef:         true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "mismatch name",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name2",
			needVersion:      true,
			allowRef:         true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "mismatch version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@v1.2.4",
			needVersion:      true,
			allowRef:         true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "invalid empty version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@",
			needVersion:      true,
			allowRef:         true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@vla@blo",
			needVersion:      true,
			allowRef:         true,
			err:              serrors.ErrorInvalidFormat,
		},
		{
			name:             "too many '@' - no need version",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@vla@blo",
			needVersion:      true,
			allowRef:         true,
			err:              serrors.ErrorInvalidFormat,
		},
		// Mismatch of tag length.
		{
			name:             "match long tag match short",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			needVersion:      true,
			allowRef:         true,
		},
		{
			name:             "long tag match short no ref",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "match long tags",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@refs/tags/v1.2.3",
			needVersion:      true,
			allowRef:         true,
		},
		{
			name:             "mismatch tag length",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "mismatch tag length inversed",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@refs/tags/v1.2.3",
			needVersion:      true,
			err:              serrors.ErrorMismatchBuilderID,
		},
		// Mismatch of tag length no need version.
		{
			name:             "match long tag match short",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			allowRef:         true,
		},
		{
			name:             "long tag match short no ref",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "match long tags",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@refs/tags/v1.2.3",
			allowRef:         true,
		},
		{
			name:             "mismatch tag length",
			trustedBuilderID: "some/name@refs/tags/v1.2.3",
			match:            "some/name@v1.2.3",
			err:              serrors.ErrorMismatchBuilderID,
		},
		{
			name:             "mismatch tag length inversed",
			trustedBuilderID: "some/name@v1.2.3",
			match:            "some/name@refs/tags/v1.2.3",
			err:              serrors.ErrorMismatchBuilderID,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			trustedBuilderID, err := TrustedBuilderIDNew(tt.trustedBuilderID, tt.needVersion)
			if err != nil {
				panic(fmt.Errorf("BuilderIDNew: %w", err))
			}

			err = trustedBuilderID.MatchesFull(tt.match, tt.allowRef)
			if !cmp.Equal(err, tt.err, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}
