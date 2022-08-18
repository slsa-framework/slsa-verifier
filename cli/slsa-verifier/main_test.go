package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/semver"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/layout"

	"github.com/slsa-framework/slsa-verifier/container"
	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/slsa-framework/slsa-verifier/verifiers/container"
)

func errCmp(e1, e2 error) bool {
	return errors.Is(e1, e2) || errors.Is(e2, e1)
}

func pString(s string) *string {
	return &s
}

const TEST_DIR = "./testdata"

var (
	ARTIFACT_PATH_BUILDERS  = []string{"go", "generic"}
	ARTIFACT_IMAGE_BUILDERS = []string{"generic_container"}
)

func getBuildersAndVersions(t *testing.T,
	optionalMinVersion string, specifiedBuilders []string,
	defaultBuilders []string,
) []string {
	res := []string{}
	builders := specifiedBuilders
	if len(builders) == 0 {
		builders = defaultBuilders
	}
	// Get versions for each builder.
	for _, builder := range builders {
		builderDir, err := ioutil.ReadDir(filepath.Join(TEST_DIR, builder))
		if err != nil {
			t.Error(err)
		}
		for _, f := range builderDir {
			// Builder subfolders are semantic version strings.
			// Compare if a min version is given.
			if f.IsDir() && (optionalMinVersion == "" ||
				semver.Compare(optionalMinVersion, f.Name()) <= 0) {
				// These are the supported versions of the builder
				res = append(res, filepath.Join(builder, f.Name()))
			}
		}
	}
	return res
}

func Test_runVerifyArtifactPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		artifact     string
		source       string
		pbranch      *string
		ptag         *string
		pversiontag  *string
		pbuilderID   *string
		outBuilderID string
		inputs       map[string]string
		err          error
		// noversion is a special case where we are not testing all builder versions
		// for example, testdata for the builder at head in trusted repo workflows
		// or testdata from malicious untrusted builders.
		// When true, this does not iterate over all builder versions.
		noversion bool
		// minversion is a special case to test a newly added feature into a builder
		minversion string
		// specifying builders will restrict builders to only the specified ones.
		builders []string
	}{
		{
			name:     "valid main branch default",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
		},
		{
			name:       "valid main branch default - invalid builderID",
			artifact:   "binary-linux-amd64-workflow_dispatch",
			source:     "github.com/slsa-framework/example-package",
			pbuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/not-trusted.yml"),
			err:        serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name:     "valid main branch set",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
			pbranch:  pString("main"),
		},
		{
			name:     "wrong branch master",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
			pbranch:  pString("master"),
			err:      serrors.ErrorMismatchBranch,
		},
		{
			name:     "branch master not verified",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
		},
		{
			name:     "wrong source append A",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/laurentsimon/slsa-verifier-test-genA",
			err:      serrors.ErrorMismatchSource,
		},
		{
			name:     "wrong source prepend A",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/laurentsimon/slsa-verifier-test-gen",
			err:      serrors.ErrorMismatchSource,
		},
		{
			name:     "wrong source middle A",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/Alaurentsimon/slsa-verifier-test-gen",
			err:      serrors.ErrorMismatchSource,
		},
		{
			name:     "tag no match empty tag workflow_dispatch",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v1.2.3"),
			err:      serrors.ErrorMismatchTag,
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch",
			artifact:    "binary-linux-amd64-workflow_dispatch",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v1"),
			err:         serrors.ErrorInvalidSemver,
		},
		// Provenance contains tag = v13.0.30.
		{
			name:     "tag v31.0.29 no match v13.0.30",
			artifact: "binary-linux-amd64-push-v13.0.30",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v13.0.29"),
			err:      serrors.ErrorMismatchTag,
		},
		{
			name:     "tag v13.0 no match v13.0.30",
			artifact: "binary-linux-amd64-push-v13.0.30",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v13.0"),
			err:      serrors.ErrorMismatchTag,
		},
		{
			name:     "tag v13 no match v13.0.30",
			artifact: "binary-linux-amd64-push-v13.0.30",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v13"),
			err:      serrors.ErrorMismatchTag,
		},
		{
			name:        "versioned v13.0.30 match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0.30"),
		},
		{
			name:        "versioned v13.0 match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0"),
		},
		{
			name:        "versioned v13 match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13"),
		},
		{
			name:        "versioned v2 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v2"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v0 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v0"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.1 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v12.9 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v12.9"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.0.29 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0.29"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.0.31 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0.31"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		// Provenance contains tag = v14.
		{
			name:        "versioned v14 match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14"),
		},
		{
			name:        "versioned v14.0 match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.0"),
		},
		{
			name:        "versioned v14.1 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.2 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.2"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v0 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v0"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		// Provenance contains tag = v14.2
		{
			name:        "versioned v14.2 match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.2"),
		},
		{
			name:        "versioned v14.2.1 match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.2.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.2.3 match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.2.3"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14 match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14"),
		},
		{
			name:        "versioned v14.1 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.1.1 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.1.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.3.1 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.3.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15.1 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		// Multiple subjects in version v1.2.0+
		{
			name:       "multiple subject first match",
			artifact:   "binary-linux-amd64-multi-subject-first",
			source:     "github.com/slsa-framework/example-package",
			minversion: "v1.2.0",
			builders:   []string{"generic"},
		},
		{
			name:       "multiple subject second match",
			artifact:   "binary-linux-amd64-multi-subject-second",
			source:     "github.com/slsa-framework/example-package",
			minversion: "v1.2.0",
			builders:   []string{"generic"},
		},
		{
			name:         "multiple subject second match - builderID",
			artifact:     "binary-linux-amd64-multi-subject-second",
			source:       "github.com/slsa-framework/example-package",
			minversion:   "v1.2.0",
			builders:     []string{"generic"},
			pbuilderID:   pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"),
			outBuilderID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml",
		},
		// Special case of the e2e test repository building builder from head.
		{
			name:         "e2e test repository verified with builder at head",
			artifact:     "binary-linux-amd64-e2e-builder-repo",
			source:       "github.com/slsa-framework/example-package",
			pbranch:      pString("main"),
			noversion:    true,
			outBuilderID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml",
		},
		// Malicious builders and workflows.
		{
			name:      "rekor upload bypassed",
			artifact:  "binary-linux-amd64-no-tlog-upload",
			source:    "github.com/slsa-framework/example-package",
			err:       serrors.ErrorNoValidRekorEntries,
			noversion: true,
		},
		{
			name:      "malicious: untrusted builder",
			artifact:  "binary-linux-amd64-untrusted-builder",
			source:    "github.com/slsa-framework/example-package",
			err:       serrors.ErrorUntrustedReusableWorkflow,
			noversion: true,
		},
		{
			name:      "malicious: invalid signature expired certificate",
			artifact:  "binary-linux-amd64-expired-cert",
			source:    "github.com/slsa-framework/example-package",
			err:       serrors.ErrorNoValidRekorEntries,
			noversion: true,
		},
		// Annotated tags.
		{
			name:        "annotated tag",
			artifact:    "annotated-tag",
			source:      "github.com/laurentsimon/slsa-on-github-test",
			pversiontag: pString("v5.0.1"),
			noversion:   true,
		},
		{
			name:        "no branch",
			artifact:    "annotated-tag",
			source:      "github.com/laurentsimon/slsa-on-github-test",
			pversiontag: pString("v5.0.1"),
			pbranch:     pString("main"),
			err:         serrors.ErrorMismatchBranch,
			noversion:   true,
		},
		// Workflow inputs.
		{
			name:     "workflow inputs match",
			artifact: "workflow-inputs",
			source:   "github.com/laurentsimon/slsa-on-github-test",
			inputs: map[string]string{
				"release_version": "v1.2.3",
				"some_bool":       "true",
				"some_integer":    "123",
			},
			noversion: true,
		},
		{
			name:     "workflow inputs missing field",
			artifact: "workflow-inputs",
			source:   "github.com/laurentsimon/slsa-on-github-test",
			inputs: map[string]string{
				"release_version": "v1.2.3",
				"some_bool":       "true",
				"missing_field":   "123",
			},
			err:       serrors.ErrorMismatchWorkflowInputs,
			noversion: true,
		},
		{
			name:     "workflow inputs mismatch",
			artifact: "workflow-inputs",
			source:   "github.com/laurentsimon/slsa-on-github-test",
			inputs: map[string]string{
				"release_version": "v1.2.3",
				"some_bool":       "true",
				"some_integer":    "321",
			},
			err:       serrors.ErrorMismatchWorkflowInputs,
			noversion: true,
		},
		// Regression test of sharded UUID.
		{
			name:      "regression: sharded uuids",
			artifact:  "binary-linux-amd64-sharded",
			source:    "github.com/slsa-framework/slsa-verifier",
			pbranch:   pString("release/v1.0"),
			noversion: true,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel()

			checkVersions := getBuildersAndVersions(t, tt.minversion, tt.builders, ARTIFACT_PATH_BUILDERS)
			if tt.noversion {
				checkVersions = []string{""}
			}

			for _, v := range checkVersions {

				artifactPath := filepath.Clean(filepath.Join(TEST_DIR, v, tt.artifact))
				provenancePath := fmt.Sprintf("%s.intoto.jsonl", artifactPath)

				_, outBuilderId, err := runVerify("", artifactPath,
					provenancePath,
					tt.source, tt.pbranch, tt.pbuilderID,
					tt.ptag, tt.pversiontag, tt.inputs)

				if !errCmp(err, tt.err) {
					t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
				}

				if err != nil {
					return
				}

				if tt.outBuilderID != "" && outBuilderId != tt.outBuilderID {
					t.Errorf(cmp.Diff(outBuilderId, tt.outBuilderID))
				}
			}
		})
	}
}

func Test_runVerifyArtifactImage(t *testing.T) {
	t.Parallel()

	// Override cosign image verification function for local image testing.
	container.RunCosignImageVerification = func(ctx context.Context,
		image string, co *cosign.CheckOpts,
	) ([]oci.Signature, bool, error) {
		return cosign.VerifyLocalImageAttestations(ctx, image, co)
	}

	// TODO: Is there a more uniform way of handling getting image digest for both
	// remote and local images?
	container.GetImageDigest = func(image string) (string, error) {
		// This is copied from cosign's VerifyLocalImageAttestation code:
		// https://github.com/sigstore/cosign/blob/fdceee4825dc5d56b130f3f431aab93137359e79/pkg/cosign/verify.go#L654
		se, err := layout.SignedImageIndex(image)
		if err != nil {
			return "", err
		}

		var h v1.Hash
		// Verify either an image index or image.
		ii, err := se.SignedImageIndex(v1.Hash{})
		if err != nil {
			return "", err
		}
		i, err := se.SignedImage(v1.Hash{})
		if err != nil {
			return "", err
		}
		switch {
		case ii != nil:
			h, err = ii.Digest()
			if err != nil {
				return "", err
			}
		case i != nil:
			h, err = i.Digest()
			if err != nil {
				return "", err
			}
		default:
			return "", errors.New("must verify either an image index or image")
		}
		return strings.TrimPrefix(h.String(), "sha256:"), nil
	}

	tests := []struct {
		name         string
		artifact     string
		source       string
		pbranch      *string
		ptag         *string
		pversiontag  *string
		pbuilderID   *string
		outBuilderID string
		err          error
		// noversion is a special case where we are not testing all builder versions
		// for example, testdata for the builder at head in trusted repo workflows
		// or testdata from malicious untrusted builders.
		// When true, this does not iterate over all builder versions.
		noversion bool
	}{
		{
			name:     "valid main branch default",
			artifact: "container_workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
		},
		{
			name:       "valid main branch default - invalid builderID",
			artifact:   "container_workflow_dispatch",
			source:     "github.com/slsa-framework/example-package",
			pbuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/not-trusted.yml"),
			err:        serrors.ErrorUntrustedReusableWorkflow,
		},

		{
			name:     "valid main branch set",
			artifact: "container_workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
			pbranch:  pString("main"),
		},

		{
			name:     "wrong branch master",
			artifact: "container_workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
			pbranch:  pString("master"),
			err:      serrors.ErrorMismatchBranch,
		},
		{
			name:     "wrong source append A",
			artifact: "container_workflow_dispatch",
			source:   "github.com/slsa-framework/example-packageA",
			err:      serrors.ErrorMismatchSource,
		},
		{
			name:     "wrong source prepend A",
			artifact: "container_workflow_dispatch",
			source:   "Agithub.com/slsa-framework/example-package",
			err:      serrors.ErrorMismatchSource,
		},
		{
			name:     "wrong source middle A",
			artifact: "container_workflow_dispatch",
			source:   "github.com/Aslsa-framework/example-package",
			err:      serrors.ErrorMismatchSource,
		},
		{
			name:     "tag no match empty tag workflow_dispatch",
			artifact: "container_workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v1.2.3"),
			err:      serrors.ErrorMismatchTag,
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch",
			artifact:    "container_workflow_dispatch",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v1"),
			err:         serrors.ErrorInvalidSemver,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkVersions := getBuildersAndVersions(t, "", nil, ARTIFACT_IMAGE_BUILDERS)
			if tt.noversion {
				checkVersions = []string{""}
			}

			for _, v := range checkVersions {
				image := filepath.Clean(filepath.Join(TEST_DIR, v, tt.artifact))

				_, outBuilderID, err := runVerify(image, "", "",
					tt.source, tt.pbranch, tt.pbuilderID,
					tt.ptag, tt.pversiontag, nil)

				if !errCmp(err, tt.err) {
					t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
				}

				if err != nil {
					return
				}

				if tt.outBuilderID != "" && outBuilderID != tt.outBuilderID {
					t.Errorf(cmp.Diff(outBuilderID, tt.outBuilderID))
				}
			}
		})
	}
}
