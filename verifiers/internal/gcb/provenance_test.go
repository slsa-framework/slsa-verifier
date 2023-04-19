package gcb

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// This function sets the statement of the provenance, as if
// it had been verified. This is necessary because individual functions
// expect this statement to be populated; and this is done only
// after the signature is verified.
func setStatement(gcb *Provenance) error {
	var statement v01IntotoStatement
	payload, err := utils.PayloadFromEnvelope(&gcb.gcloudProv.ProvenanceSummary.Provenance[0].Envelope)
	if err != nil {
		return fmt.Errorf("payloadFromEnvelope: %w", err)
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	gcb.verifiedIntotoStatement = &statement
	gcb.verifiedProvenance = &gcb.gcloudProv.ProvenanceSummary.Provenance[0]
	return nil
}

func Test_VerifyIntotoHeaders(t *testing.T) {
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}

			err = prov.VerifyIntotoHeaders()
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifyBuilder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		path      string
		builderID string
		expected  error
	}{
		{
			name:      "valid gcb provenance",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
		},
		{
			name:      "valid gcb provenance gcs",
			path:      "./testdata/gcloud-container-gcs.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
		},
		{
			name:      "mismatch builder.id version",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.1",
			expected:  serrors.ErrorMismatchBuilderID,
		},
		{
			name:      "mismatch builder.id name",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorke@v0.2",
			expected:  serrors.ErrorMismatchBuilderID,
		},
		{
			name:      "mismatch builder.id protocol",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "http://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			expected:  serrors.ErrorMismatchBuilderID,
		},
		{
			name:     "mismatch recipe.arguments.type",
			path:     "./testdata/gcloud-container-invalid-recipe.arguments.type.json",
			expected: serrors.ErrorMismatchBuilderID,
		},
		{
			name:     "v0.2 mismatch recipe.type",
			path:     "./testdata/gcloud-container-invalid-recipe.type.json",
			expected: serrors.ErrorInvalidRecipe,
		},
		{
			name:      "v0.1 invalid builder",
			path:      "./testdata/gcloud-container-invalid-builderv01.json",
			builderID: "http://cloudbuild.googleapis.com/GoogleHostedWorker@v0.1",
			expected:  serrors.ErrorInvalidBuilderID,
		},
		{
			name:      "invalid v0.2 recipe type CloudBuildSteps",
			path:      "./testdata/gcloud-container-invalid-recipetypestepsv02.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			expected:  serrors.ErrorInvalidRecipe,
		},
		{
			name:      "invalid v0.2 recipe type CloudBuildYaml",
			path:      "./testdata/gcloud-container-invalid-recipetypecloudv02.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			expected:  serrors.ErrorInvalidRecipe,
		},
		{
			name:      "valid v0.3 recipe type CloudBuildSteps",
			path:      "./testdata/gcloud-container-invalid-recipetypestepsv03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
		},
		{
			name:      "valid v0.3 recipe type CloudBuildYaml",
			path:      "./testdata/gcloud-container-invalid-recipetypecloudv03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
		},
		{
			name:      "invalid v0.3 recipe type random",
			path:      "./testdata/gcloud-container-invalid-recipetyperandv03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
			expected:  serrors.ErrorInvalidRecipe,
		},
		{
			name:      "v0.2 valid builder - name only",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker",
		},
		{
			name:      "v0.2 mismatch builder - name only",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorke",
			expected:  serrors.ErrorMismatchBuilderID,
		},
		{
			name:      "v0.3 valid builder CloudBuildSteps - name only",
			path:      "./testdata/gcloud-container-invalid-recipetypestepsv03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker",
		},
		{
			name:      "v0.3 valid builder CloudBuildYaml - name only",
			path:      "./testdata/gcloud-container-invalid-recipetypecloudv03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker",
		},
		{
			name:      "v0.3 mismatch builder CloudBuildSteps - name only",
			path:      "./testdata/gcloud-container-invalid-recipetypestepsv03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorke",
			expected:  serrors.ErrorMismatchBuilderID,
		},
		{
			name:      "v0.3 mismatch CloudBuildYaml - name only",
			path:      "./testdata/gcloud-container-invalid-recipetypecloudv03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorke",
			expected:  serrors.ErrorMismatchBuilderID,
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}

			var builderOpts options.BuilderOpts
			if tt.builderID != "" {
				builderOpts.ExpectedID = &tt.builderID
			}
			outBuilderID, err := prov.VerifyBuilder(&builderOpts)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}

			if err != nil {
				return
			}

			if outBuilderID == nil {
				panic("outBuilderID is nil")
			}

			if err := outBuilderID.MatchesLoose(tt.builderID, false); err != nil {
				t.Errorf(fmt.Sprintf("matches failed: %v", err))
			}
		})
	}
}

func Test_validateRecipeType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		builderID  string
		recipeType string
		expected   error
	}{
		// v0.2 builder.
		{
			name:       "valid v0.2 recipe type",
			builderID:  "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			recipeType: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
		},
		{
			name:       "invalid v0.2 recipe type CloudBuildYaml",
			builderID:  "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			recipeType: "https://cloudbuild.googleapis.com/CloudBuildYaml@v0.1",
			expected:   serrors.ErrorInvalidRecipe,
		},
		{
			name:       "invalid v0.2 recipe type CloudBuildSteps",
			builderID:  "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			recipeType: "https://cloudbuild.googleapis.com/CloudBuildSteps@v0.1",
			expected:   serrors.ErrorInvalidRecipe,
		},
		// v0.3 builder.
		{
			name:       "valid v0.3 recipe type CloudBuildYaml",
			builderID:  "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
			recipeType: "https://cloudbuild.googleapis.com/CloudBuildYaml@v0.1",
		},
		{
			name:       "valid v0.3 recipe type CloudBuildSteps",
			builderID:  "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
			recipeType: "https://cloudbuild.googleapis.com/CloudBuildSteps@v0.1",
		},
		{
			name:       "invalid v0.3 recipe type GoogleHostedWorker",
			builderID:  "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
			recipeType: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			expected:   serrors.ErrorInvalidRecipe,
		},
		// No version.
		{
			name:       "invalid builder version",
			builderID:  "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.1",
			recipeType: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.1",
			expected:   serrors.ErrorInvalidBuilderID,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			builderID, err := utils.TrustedBuilderIDNew(tt.builderID, true)
			if err != nil {
				panic(fmt.Errorf("BuilderIDNew: %w", err))
			}
			err = validateRecipeType(*builderID, tt.recipeType)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifySourceURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		path      string
		builderID string
		source    string
		expected  error
	}{
		// v0.1
		{
			name:      "v0.1 invalid builder id",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.1",
			source:    "https://github.com/laurentsimon/gcb-tests",
			expected:  serrors.ErrorInvalidBuilderID,
		},
		// v0.2
		{
			name:      "v0.2 valid gcb provenance",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "https://github.com/laurentsimon/gcb-tests",
		},
		{
			name:      "v0.2 mismatch name",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "https://github.com/laurentsimon/gcb-tests2",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.2 mismatch org",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "https://github.com/wrong/gcb-tests",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.2 mismatch protocol",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "http://github.com/laurentsimon/gcb-tests",
			expected:  serrors.ErrorMismatchSource,
		},
		// We disallow matches on full commits intentionally. Matching on the commit
		// SHA should be viewed as a separate match.
		{
			name:      "v0.2 mismatch full uri",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "https://github.com/laurentsimon/gcb-tests/commit/fbbb98765e85ad464302dc5977968104d36e455e",
			expected:  serrors.ErrorMismatchSource,
		},
		// v0.2 GCS source
		{
			name:      "v0.2 valid match gcb gcs provenance",
			path:      "./testdata/gcloud-container-gcs.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "gs://damith-sds_cloudbuild/source/1665165360.279777-955d1904741e4bbeb3461080299e929a.tgz",
		},
		{
			name:      "v0.2 mismatch match full uri gcs with fragment",
			path:      "./testdata/gcloud-container-gcs.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "gs://damith-sds_cloudbuilds/source/1665165360.279777-955d1904741e4bbeb3461080299e929a.tgz#1665165361152729",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.2 mistmach gcb provenance incomplete gcs bucket",
			path:      "./testdata/gcloud-container-gcs.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "gs://damith-sds_cloudbuild/source",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.2 mismatch path gcb gcs provenance",
			path:      "./testdata/gcloud-container-gcs.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "gs://damith-sds_cloudbuilds/source/1665165360.279777-955d1904741e4bbeb3461080299e929a.tgz",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.2 mismatch scheme gcb gcs provenance",
			path:      "./testdata/gcloud-container-gcs.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "https://damith-sds_cloudbuild/source/1665165360.279777-955d1904741e4bbeb3461080299e929a.tgz",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.2 mismatch path source gcb gcs provenance",
			path:      "./testdata/gcloud-container-gcs.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "gs://damith-sds_cloudbuild/sources/1665165360.279777-955d1904741e4bbeb3461080299e929a.tgz",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.2 mismatch path tar gcb gcs provenance",
			path:      "./testdata/gcloud-container-gcs.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "gs://damith-sds_cloudbuild/source/2665165360.279777-955d1904741e4bbeb3461080299e929a.tgz",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.2 mismatch fragment gcb gcs provenance",
			path:      "./testdata/gcloud-container-gcs.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "gs://damith-sds_cloudbuild/source/1665165360.279777-955d1904741e4bbeb3461080299e929a.tgz#2665165361152729",
			expected:  serrors.ErrorMismatchSource,
		},
		// v0.3
		{
			name:      "v0.3 valid gcb provenance",
			path:      "./testdata/gcloud-container-github-v03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
			source:    "https://github.com/laurentsimon/gcb-tests",
		},
		{
			name:      "v0.3 valid gcb provenance with git prefix",
			path:      "./testdata/gcloud-container-github-v03-git.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
			source:    "https://github.com/slsa-framework/example-package",
		},
		{
			name:      "v0.3 mismatch name",
			path:      "./testdata/gcloud-container-github-v03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
			source:    "https://github.com/laurentsimon/gcb-tests2",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.3 mismatch org",
			path:      "./testdata/gcloud-container-github-v03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
			source:    "https://github.com/wrong/gcb-tests",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.3 mismatch protocol",
			path:      "./testdata/gcloud-container-github-v03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			source:    "http://github.com/laurentsimon/gcb-tests",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.3 mismatch full uri",
			path:      "./testdata/gcloud-container-github-v03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
			source:    "https://github.com/laurentsimon/gcb-tests/commit/fbbb98765e85ad464302dc5977968104d36e455e",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name:      "v0.3 mismatch full uri uses v0.2 format",
			path:      "./testdata/gcloud-container-github-v03.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
			source:    "https://github.com/laurentsimon/gcb-tests/commit/01ce393d04eb6df2a7b2b3e95d4126e687afb7ae",
			expected:  serrors.ErrorMismatchSource,
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}

			builderID, err := utils.TrustedBuilderIDNew(tt.builderID, true)
			if err != nil {
				panic(fmt.Errorf("BuilderIDNew: %w", err))
			}
			err = prov.VerifySourceURI(tt.source, *builderID)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifySignature(t *testing.T) {
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
			name: "global gcb signing key",
			path: "./testdata/gcloud-container-global-pae-signing-key-successful.json",
		},
		{
			name:     "invalid signature",
			path:     "./testdata/gcloud-container-invalid-signature.json",
			expected: serrors.ErrorNoValidSignature,
		},
		{
			name:     "invalid signature",
			path:     "./testdata/gcloud-container-invalid-signature-payloadtype.json",
			expected: serrors.ErrorNoValidSignature,
		},
		{
			name:     "invalid signature - global PAE key",
			path:     "./testdata/gcloud-container-invalid-signature-global-pae-key.json",
			expected: serrors.ErrorNoValidSignature,
		},
		{
			name:     "invalid signature empty",
			path:     "./testdata/gcloud-container-empty-signature.json",
			expected: serrors.ErrorNoValidSignature,
		},
		{
			name:     "invalid region",
			path:     "./testdata/gcloud-container-invalid-signature-region.json",
			expected: serrors.ErrorNoValidSignature,
		},
		{
			name:     "invalid region empty",
			path:     "./testdata/gcloud-container-empty-signature-region.json",
			expected: serrors.ErrorNoValidSignature,
		},
		{
			name:     "invalid keyid",
			path:     "./testdata/gcloud-container-invalid-keyid.json",
			expected: serrors.ErrorNoValidSignature,
		},
		{
			name:     "invalid keyid empty",
			path:     "./testdata/gcloud-container-empty-keyid.json",
			expected: serrors.ErrorNoValidSignature,
		},
		{
			name:     "invalid keyid none",
			path:     "./testdata/gcloud-container-no-keyid.json",
			expected: serrors.ErrorNoValidSignature,
		},
		{
			name:     "invalid signature multiple",
			path:     "./testdata/gcloud-container-multiple-invalid-signatures.json",
			expected: serrors.ErrorNoValidSignature,
		},
		{
			name: "signature multiple 2nd valid",
			path: "./testdata/gcloud-container-multiple-signatures-2ndvalid.json",
		},
		{
			name: "signature multiple 3rd valid",
			path: "./testdata/gcloud-container-multiple-signatures-3rdvalid.json",
		},
		{
			name: "signature multiple global pae valid",
			path: "./testdata/gcloud-container-multiple-signatures-global-pae-valid.json",
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}
			err = prov.VerifySignature()
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_ProvenanceFromBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		expected error
	}{
		{
			name:     "invalid signature none",
			path:     "./testdata/gcloud-container-no-signature.json",
			expected: serrors.ErrorInvalidDssePayload,
		},
		{
			name:     "invalid provenance empty",
			path:     "./testdata/gcloud-container-empty-provenance.json",
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

			_, err = ProvenanceFromBytes(content)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifySubjectDigest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		hash     string
		expected error
	}{
		{
			name: "valid gcb provenance",
			path: "./testdata/gcloud-container-github.json",
			hash: "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
		},
		{
			name:     "mismatch hash",
			path:     "./testdata/gcloud-container-github.json",
			hash:     "0a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
			expected: serrors.ErrorMismatchHash,
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}

			err = prov.VerifySubjectDigest(tt.hash)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifySummary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		hash     string
		expected error
	}{
		{
			name: "valid gcb provenance",
			path: "./testdata/gcloud-container-github.json",
			hash: "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
		},
		{
			name: "valid gcb provenance gcs",
			path: "./testdata/gcloud-container-gcs.json",
			hash: "9dcfacc497b61c4d2ff5708e644c060726781fae514dc8ba71c49dced675bcbe",
		},
		{
			name:     "mismatch digest",
			path:     "./testdata/gcloud-container-github.json",
			hash:     "2a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
			expected: serrors.ErrorMismatchHash,
		},
		{
			name:     "mismatch fuly qualified digest",
			path:     "./testdata/gcloud-container-invalid-fullyqualifieddigest.json",
			hash:     "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
			expected: serrors.ErrorMismatchHash,
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}

			provenanceOpts := options.ProvenanceOpts{
				ExpectedDigest: tt.hash,
			}
			err = prov.VerifySummary(&provenanceOpts)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifyMetadata(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		hash     string
		expected error
	}{
		{
			name: "valid gcb provenance",
			path: "./testdata/gcloud-container-github.json",
			hash: "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
		},
		{
			name:     "mismatch hash",
			path:     "./testdata/gcloud-container-github.json",
			hash:     "2a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
			expected: serrors.ErrorMismatchHash,
		},
		{
			name:     "invalid kind",
			path:     "./testdata/gcloud-container-invalid-kind.json",
			hash:     "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
			expected: serrors.ErrorInvalidFormat,
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}

			provenanceOpts := options.ProvenanceOpts{
				ExpectedDigest: tt.hash,
			}
			err = prov.VerifyMetadata(&provenanceOpts)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifyTextProvenance(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		alter    bool
		expected error
	}{
		{
			name: "valid gcb provenance",
			path: "./testdata/gcloud-container-github.json",
		},
		{
			name: "valid gcb provenance with global signing key",
			path: "./testdata/gcloud-container-global-pae-signing-key-successful.json",
		},
		{
			name:     "mismatch everything",
			path:     "./testdata/gcloud-container-github.json",
			alter:    true,
			expected: serrors.ErrorMismatchIntoto,
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}

			if !tt.alter {
				err = prov.VerifyTextProvenance()
				if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
					t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
				}
				return
			}

			// Alter fields.
			cpy, err := json.Marshal(prov.verifiedProvenance.Build.UnverifiedTextIntotoStatement)
			if err != nil {
				panic(err)
			}
			chars := map[byte]bool{',': true, ':': true, '[': true, ']': true, '{': true, '}': true, '"': true}
			patch := []byte(strings.Clone(string(cpy)))
			i := 0
			for i < len(patch) {
				// If it's a character that changes the JSON format, ignore it.
				if _, ok := chars[patch[i]]; ok {
					i++
					continue
				}

				ni, ctned := isFieldName(i, patch)
				if !ctned {
					i = ni
					continue
				}

				// Update the string representation.
				switch {
				case len(patch[i:]) >= 5 && string(patch[i:i+5]) == "false":
					// Update `false` booleans.
					t := append([]byte("true"), patch[i+5:]...)
					patch = append(patch[:i], t...)
					i += 4
				case len(patch[i:]) >= 4 && string(patch[i:i+4]) == "true":
					// Update `true` booleans.
					t := append([]byte("false"), patch[i+4:]...)
					patch = append(patch[:i], t...)
					i += 5
				default:
					// Update characters.
					patch[i] += 1
				}

				if err = json.Unmarshal(patch, &prov.verifiedProvenance.Build.UnverifiedTextIntotoStatement); err != nil {
					// If we updated a character that makes a non-string field invalid, like Time, unmarshaling will fail,
					// so we ignore the error.
					i += 1
					patch = []byte(strings.Clone(string(cpy)))
					continue
				}
				err = prov.VerifyTextProvenance()
				if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
					t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
				}
				// Start with the original string value.
				patch = []byte(strings.Clone(string(cpy)))
				i += 1
			}
		})
	}
}

func isFieldName(i int, content []byte) (int, bool) {
	j := i
	for j < len(content) {
		if string(content[j]) == "}" ||
			string(content[j]) == "," {
			return i, true
		}
		if string(content[j:j+2]) == "\":" {
			i = j + 2
			return i, false
		}
		j += 1
	}
	return i, true
}

func Test_VerifyBranch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		branch   string
		expected error
	}{
		{
			name:     "valid gcb provenance",
			path:     "./testdata/gcloud-container-github.json",
			branch:   "master",
			expected: serrors.ErrorNotSupported,
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}

			err = prov.VerifyBranch(tt.branch)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
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
			path:  "./testdata/gcloud-container-tag.json",
			field: "TAG_NAME",
			value: "v33.0.4",
		},
		{
			name:  "match repo name",
			path:  "./testdata/gcloud-container-tag.json",
			field: "REPO_NAME",
			value: "example-package",
		},
		{
			name:  "no substitutions field",
			path:  "./testdata/gcloud-container-github.json",
			field: "TAG_NAME",
			err:   errorSubstitutionError,
		},
		{
			name:  "tag not present",
			path:  "./testdata/gcloud-container-tag-notpresent.json",
			field: "TAG_NAME",
			err:   errorSubstitutionError,
		},
		{
			name:  "tag not string",
			path:  "./testdata/gcloud-container-tag-notstring.json",
			field: "TAG_NAME",
			err:   errorSubstitutionError,
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}

			value, err := getSubstitutionsField(prov.verifiedIntotoStatement, tt.field)
			if !cmp.Equal(err, tt.err, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
			}
			if err != nil && !cmp.Equal(value, tt.value) {
				t.Errorf(cmp.Diff(value, tt.value))
			}
		})
	}
}

func Test_VerifyTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		tag  string
		err  error
	}{
		{
			name: "match tag",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v33.0.4",
		},
		{
			name: "no match major only",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v33",
			err:  serrors.ErrorMismatchTag,
		},
		{
			name: "no match major and minor only",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v33.0",
			err:  serrors.ErrorMismatchTag,
		},
		{
			name: "no match major",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v34.0.4",
			err:  serrors.ErrorMismatchTag,
		},
		{
			name: "no substitutions field",
			path: "./testdata/gcloud-container-github.json",
			err:  serrors.ErrorMismatchTag,
		},
		{
			name: "tag not present",
			path: "./testdata/gcloud-container-tag-notpresent.json",
			err:  serrors.ErrorMismatchTag,
		},
		{
			name: "tag not string",
			path: "./testdata/gcloud-container-tag-notstring.json",
			err:  serrors.ErrorMismatchTag,
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}

			err = prov.VerifyTag(tt.tag)
			if !cmp.Equal(err, tt.err, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifyVersionedTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		tag  string
		err  error
	}{
		{
			name: "match tag",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v33.0.4",
		},
		{
			name: "match minor",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v33.0",
		},
		{
			name: "no match minor",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v33.1",
			err:  serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "no match minor with patch",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v33.1.0",
			err:  serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "match major",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v33",
		},
		{
			name: "no match major greater",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v34",
			err:  serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "no match major greater with minor",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v34.0",
			err:  serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "no match major greater with minor and patch",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v34.0.4",
			err:  serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "no match major lower",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v32",
			err:  serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "no match major lower with minor",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v32.0",
			err:  serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "no match major lower with minor and patch",
			path: "./testdata/gcloud-container-tag.json",
			tag:  "v32.0.4",
			err:  serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "no substitutions field",
			path: "./testdata/gcloud-container-github.json",
			err:  serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag not present",
			path: "./testdata/gcloud-container-tag-notpresent.json",
			err:  serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag not string",
			path: "./testdata/gcloud-container-tag-notstring.json",
			err:  serrors.ErrorMismatchVersionedTag,
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

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("setStatement: %w", err))
			}

			err = prov.VerifyVersionedTag(tt.tag)
			if !cmp.Equal(err, tt.err, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
			}
		})
	}
}
