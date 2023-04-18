//go:build regression

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/semver"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"

	"github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier/verify"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils/container"
)

func errCmp(e1, e2 error) bool {
	return errors.Is(e1, e2) || errors.Is(e2, e1)
}

func pString(s string) *string {
	return &s
}

const TEST_DIR = "./testdata"

var (
	GHA_ARTIFACT_PATH_BUILDERS = []string{"gha_go", "gha_generic"}
	// TODO(https://github.com/slsa-framework/slsa-verifier/issues/485): Merge this with
	// GHA_ARTIFACT_PATH_BUILDERS.
	GHA_ARTIFACT_DOCKER_BUILDERS = []string{"gha_docker-based"}
	GHA_ARTIFACT_IMAGE_BUILDERS  = []string{"gha_generic_container"}
	GCB_ARTIFACT_IMAGE_BUILDERS  = []string{"gcb_container"}
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

func Test_runVerifyGHAArtifactPath(t *testing.T) {
	t.Parallel()
	goBuilder := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml"
	genericBuilder := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"

	tests := []struct {
		name         string
		artifacts    []string
		source       string
		pbranch      *string
		ptag         *string
		pversiontag  *string
		pBuilderID   *string
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
		// specify provenance path if not the same as artifacts[0]
		// useful for testing provenance with multiple artifacts,
		// without needing to duplicate provenance
		provenancePath string
	}{
		{
			name:      "valid main branch default",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/slsa-framework/example-package",
		},
		{
			name:       "valid main branch default - invalid builderID",
			artifacts:  []string{"binary-linux-amd64-workflow_dispatch"},
			source:     "github.com/slsa-framework/example-package",
			pBuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/not-trusted.yml"),
			err:        serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name:      "valid main branch set",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/slsa-framework/example-package",
			pbranch:   pString("main"),
		},
		{
			name:      "wrong branch master",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/slsa-framework/example-package",
			pbranch:   pString("master"),
			err:       serrors.ErrorMismatchBranch,
		},
		{
			name:      "branch master not verified",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/slsa-framework/example-package",
		},
		{
			name:      "wrong source append A",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/laurentsimon/slsa-verifier-test-genA",
			err:       serrors.ErrorMismatchSource,
		},
		{
			name:      "wrong source prepend A",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/laurentsimon/slsa-verifier-test-gen",
			err:       serrors.ErrorMismatchSource,
		},
		{
			name:      "wrong source middle A",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/Alaurentsimon/slsa-verifier-test-gen",
			err:       serrors.ErrorMismatchSource,
		},
		{
			name:      "tag no match empty tag workflow_dispatch",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/slsa-framework/example-package",
			ptag:      pString("v1.2.3"),
			err:       serrors.ErrorMismatchTag,
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch",
			artifacts:   []string{"binary-linux-amd64-workflow_dispatch"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v1"),
			err:         serrors.ErrorInvalidSemver,
		},
		// Provenance contains tag = v13.0.30.
		{
			name:      "tag v13.0.29 no match v13.0.30",
			artifacts: []string{"binary-linux-amd64-push-v13.0.30"},
			source:    "github.com/slsa-framework/example-package",
			ptag:      pString("v13.0.29"),
			err:       serrors.ErrorMismatchTag,
		},
		{
			name:      "tag v13.0 no match v13.0.30",
			artifacts: []string{"binary-linux-amd64-push-v13.0.30"},
			source:    "github.com/slsa-framework/example-package",
			ptag:      pString("v13.0"),
			err:       serrors.ErrorMismatchTag,
		},
		{
			name:      "tag v13 no match v13.0.30",
			artifacts: []string{"binary-linux-amd64-push-v13.0.30"},
			source:    "github.com/slsa-framework/example-package",
			ptag:      pString("v13"),
			err:       serrors.ErrorMismatchTag,
		},
		{
			name:        "versioned v13.0.30 match push-v13.0.30",
			artifacts:   []string{"binary-linux-amd64-push-v13.0.30"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0.30"),
		},
		{
			name:        "versioned v13.0 match push-v13.0.30",
			artifacts:   []string{"binary-linux-amd64-push-v13.0.30"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0"),
		},
		{
			name:        "versioned v13 match push-v13.0.30",
			artifacts:   []string{"binary-linux-amd64-push-v13.0.30"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13"),
		},
		{
			name:        "versioned v2 no match push-v13.0.30",
			artifacts:   []string{"binary-linux-amd64-push-v13.0.30"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v2"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v0 no match push-v13.0.30",
			artifacts:   []string{"binary-linux-amd64-push-v13.0.30"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v0"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.1 no match push-v13.0.30",
			artifacts:   []string{"binary-linux-amd64-push-v13.0.30"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v12.9 no match push-v13.0.30",
			artifacts:   []string{"binary-linux-amd64-push-v13.0.30"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v12.9"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.0.29 no match push-v13.0.30",
			artifacts:   []string{"binary-linux-amd64-push-v13.0.30"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0.29"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.0.31 no match push-v13.0.30",
			artifacts:   []string{"binary-linux-amd64-push-v13.0.30"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0.31"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		// Provenance contains tag = v14.
		{
			name:        "versioned v14 match push-v14",
			artifacts:   []string{"binary-linux-amd64-push-v14"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14"),
		},
		{
			name:        "versioned v14.0 match push-v14",
			artifacts:   []string{"binary-linux-amd64-push-v14"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.0"),
		},
		{
			name:        "versioned v14.1 no match push-v14",
			artifacts:   []string{"binary-linux-amd64-push-v14"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13 no match push-v14",
			artifacts:   []string{"binary-linux-amd64-push-v14"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14",
			artifacts:   []string{"binary-linux-amd64-push-v14"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.2 no match push-v14",
			artifacts:   []string{"binary-linux-amd64-push-v14"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.2"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14",
			artifacts:   []string{"binary-linux-amd64-push-v14"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v0 no match push-v14",
			artifacts:   []string{"binary-linux-amd64-push-v14"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v0"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		// Provenance contains tag = v14.2
		{
			name:        "versioned v14.2 match push-v14.2",
			artifacts:   []string{"binary-linux-amd64-push-v14.2"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.2"),
		},
		{
			name:        "versioned v14.2.1 match push-v14.2",
			artifacts:   []string{"binary-linux-amd64-push-v14.2"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.2.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.2.3 match push-v14.2",
			artifacts:   []string{"binary-linux-amd64-push-v14.2"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.2.3"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14 match push-v14.2",
			artifacts:   []string{"binary-linux-amd64-push-v14.2"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14"),
		},
		{
			name:        "versioned v14.1 no match push-v14.2",
			artifacts:   []string{"binary-linux-amd64-push-v14.2"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.1.1 no match push-v14.2",
			artifacts:   []string{"binary-linux-amd64-push-v14.2"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.1.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.3.1 no match push-v14.2",
			artifacts:   []string{"binary-linux-amd64-push-v14.2"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.3.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13 no match push-v14.2",
			artifacts:   []string{"binary-linux-amd64-push-v14.2"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14.2",
			artifacts:   []string{"binary-linux-amd64-push-v14.2"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15.1 no match push-v14.2",
			artifacts:   []string{"binary-linux-amd64-push-v14.2"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15.1"),
			err:         serrors.ErrorMismatchVersionedTag,
		},
		// Multiple subjects in version v1.2.0+
		{
			name:      "multiple subject first match",
			artifacts: []string{"binary-linux-amd64-multi-subject-first"},
			source:    "github.com/slsa-framework/example-package",
			noversion: true,
			builders:  []string{"gha_generic"},
		},
		{
			name:      "multiple subject second match",
			artifacts: []string{"binary-linux-amd64-multi-subject-second"},
			source:    "github.com/slsa-framework/example-package",
			noversion: true,
			builders:  []string{"gha_generic"},
		},
		{
			name:      "multiple subject first and second match",
			artifacts: []string{"binary-linux-amd64-multi-subject-first", "binary-linux-amd64-multi-subject-second"},
			source:    "github.com/slsa-framework/example-package",
			noversion: true,
			builders:  []string{"gha_generic"},
		},
		{
			name:      "multiple subject second and first match",
			artifacts: []string{"binary-linux-amd64-multi-subject-second", "binary-linux-amd64-multi-subject-first"},
			source:    "github.com/slsa-framework/example-package",
			noversion: true,
			builders:  []string{"gha_generic"},
		},
		{
			name:      "multiple subject repeated match",
			artifacts: []string{"binary-linux-amd64-multi-subject-first", "binary-linux-amd64-multi-subject-first"},
			source:    "github.com/slsa-framework/example-package",
			noversion: true,
			builders:  []string{"gha_generic"},
		},
		{
			name:      "multiple subject one mismatch",
			artifacts: []string{"binary-linux-amd64-multi-subject-first", "binary-linux-amd64-sharded"},
			source:    "github.com/slsa-framework/example-package",
			noversion: true,
			err:       serrors.ErrorMismatchHash,
		},
		{
			name:           "multiple subject no match",
			artifacts:      []string{"binary-linux-amd64-sharded"},
			source:         "github.com/slsa-framework/example-package",
			noversion:      true,
			err:            serrors.ErrorMismatchHash,
			provenancePath: "binary-linux-amd64-multi-subject-first.intoto.jsonl",
		},
		{
			name:         "multiple subject second match - builderID",
			artifacts:    []string{"binary-linux-amd64-multi-subject-second"},
			source:       "github.com/slsa-framework/example-package",
			noversion:    true,
			builders:     []string{"gha_generic"},
			pBuilderID:   pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"),
			outBuilderID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml",
		},
		// Special case of the e2e test repository building builder from head.
		{
			name:         "e2e test repository verified with builder at head",
			artifacts:    []string{"binary-linux-amd64-e2e-builder-repo"},
			source:       "github.com/slsa-framework/example-package",
			pbranch:      pString("main"),
			noversion:    true,
			pBuilderID:   pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml"),
			outBuilderID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml",
		},
		// Malicious builders and workflows.
		{
			name:      "rekor upload bypassed",
			artifacts: []string{"binary-linux-amd64-no-tlog-upload"},
			source:    "github.com/slsa-framework/example-package",
			err:       serrors.ErrorRekorSearch,
			noversion: true,
		},
		{
			name:      "malicious: untrusted builder",
			artifacts: []string{"binary-linux-amd64-untrusted-builder"},
			source:    "github.com/slsa-framework/example-package",
			err:       serrors.ErrorUntrustedReusableWorkflow,
			noversion: true,
		},
		{
			name:      "malicious: invalid signature expired certificate",
			artifacts: []string{"binary-linux-amd64-expired-cert"},
			source:    "github.com/slsa-framework/example-package",
			err:       serrors.ErrorRekorSearch,
			noversion: true,
		},
		// Annotated tags.
		{
			name:        "annotated tag",
			artifacts:   []string{"annotated-tag"},
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1.5.0"),
			noversion:   true,
		},
		{
			name:        "no branch",
			artifacts:   []string{"annotated-tag"},
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1.5.0"),
			pbranch:     pString("main"),
			err:         serrors.ErrorMismatchBranch,
			noversion:   true,
		},
		// Workflow inputs.
		{
			name:      "workflow inputs match",
			artifacts: []string{"workflow-inputs"},
			source:    "github.com/laurentsimon/slsa-on-github-test",
			inputs: map[string]string{
				"release_version": "(for example, 0.1.0)",
				"some_bool":       "true",
				"some_integer":    "123",
			},
			noversion: true,
		},
		{
			name:      "workflow inputs missing field",
			artifacts: []string{"workflow-inputs"},
			source:    "github.com/laurentsimon/slsa-on-github-test",
			inputs: map[string]string{
				"release_version": "(for example, 0.1.0)",
				"some_bool":       "true",
				"missing_field":   "123",
			},
			err:       serrors.ErrorMismatchWorkflowInputs,
			noversion: true,
		},
		{
			name:      "workflow inputs mismatch",
			artifacts: []string{"workflow-inputs"},
			source:    "github.com/laurentsimon/slsa-on-github-test",
			inputs: map[string]string{
				"release_version": "(for example, 0.1.0)",
				"some_bool":       "true",
				"some_integer":    "321",
			},
			err:       serrors.ErrorMismatchWorkflowInputs,
			noversion: true,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			// Avoid rate limiting by not running the tests in parallel.
			// t.Parallel()
			checkVersions := getBuildersAndVersions(t, "v1.2.2", tt.builders, GHA_ARTIFACT_PATH_BUILDERS)
			if tt.noversion {
				checkVersions = []string{""}
			}

			for _, v := range checkVersions {
				var provenancePath string
				if tt.provenancePath == "" {
					testPath := filepath.Clean(filepath.Join(TEST_DIR, v, tt.artifacts[0]))
					provenancePath = fmt.Sprintf("%s.intoto.jsonl", testPath)
				} else {
					provenancePath = filepath.Clean(filepath.Join(TEST_DIR, v, tt.provenancePath))
				}

				artifacts := make([]string, len(tt.artifacts))
				for i, artifact := range tt.artifacts {
					artifacts[i] = filepath.Clean(filepath.Join(TEST_DIR, v, artifact))
				}

				// TODO(#258): invalid builder ref.
				sv := path.Base(v)
				// For each test, we run 4 sub-tests:
				// 	1. With the the full builderID including the semver in short form.
				//	2. With the the full builderID including the semver in long form.
				//	3. With only the name of the builder.
				//	4. With no builder ID.
				var builder string
				// Select the right builder based on directory structure.
				parts := strings.Split(v, "/")
				name := parts[0]
				version := ""
				if len(parts) > 1 {
					version = parts[1]
				}
				switch {
				case strings.HasSuffix(name, "_go"):
					builder = goBuilder
				case strings.HasSuffix(name, "_generic"):
					builder = genericBuilder
				default:
					builder = genericBuilder
				}

				// Default builders to test.
				builderIDs := []*string{
					pString(builder),
					nil,
				}

				// We only add the tags to tests for versions >= 1,
				// because we generated them with a builder at `@main`
				// before GA. Add the tests for tag verification.
				if version != "" && semver.Compare(version, "v1.0.0") > 0 {
					builderIDs = append(builderIDs, []*string{
						pString(builder + "@" + sv),
						pString(builder + "@refs/tags/" + sv),
					}...)
				}

				// If builder ID is set, use it.
				if tt.pBuilderID != nil {
					builderIDs = []*string{tt.pBuilderID}
				}

				for _, bid := range builderIDs {
					cmd := verify.VerifyArtifactCommand{
						ProvenancePath:      provenancePath,
						SourceURI:           tt.source,
						SourceBranch:        tt.pbranch,
						BuilderID:           bid,
						SourceTag:           tt.ptag,
						SourceVersionTag:    tt.pversiontag,
						BuildWorkflowInputs: tt.inputs,
					}

					// The outBuilderID is the actual builder ID from the provenance.
					// This is always long form for the GHA builders.
					outBuilderID, err := cmd.Exec(context.Background(), artifacts)
					if !errCmp(err, tt.err) {
						t.Errorf("%v: %v", v, cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
					}

					if err != nil {
						continue
					}

					// Validate against test's expected builderID, if provided.
					if tt.outBuilderID != "" {
						if err := outBuilderID.Matches(tt.outBuilderID, false); err != nil {
							t.Errorf(fmt.Sprintf("matches failed (1): %v", err))
						}
					}

					// Smoke test against the CLI command
					cliCmd := verifyArtifactCmd()
					args := []string{
						"--source-uri", tt.source,
						"--provenance-path", provenancePath,
					}
					args = append(args, artifacts...)
					if bid != nil {
						args = append(args, "--builder-id", *bid)
					}
					if tt.pbranch != nil {
						args = append(args, "--source-branch", *tt.pbranch)
					}
					if tt.ptag != nil {
						args = append(args, "--source-tag", *tt.ptag)
					}
					if tt.pversiontag != nil {
						args = append(args, "--source-versioned-tag", *tt.pversiontag)
					}
					if tt.inputs != nil {
						for k, v := range tt.inputs {
							args = append(args, "--build-workflow-input", fmt.Sprintf("%s=%s", k, v))
						}
					}
					b := bytes.NewBufferString("")
					cliCmd.SetOut(b)
					cliCmd.SetArgs(args)
					cliErr := cliCmd.Execute()
					if !errCmp(cliErr, tt.err) {
						t.Errorf("%v: %v", v, cmp.Diff(cliErr, tt.err, cmpopts.EquateErrors()))
					}

					if bid == nil {
						continue
					}

					// If we have a generated a user-provided bid, then validate it against the
					// resulting builderID returned by the provenance check.
					// Since this a GHA and the certificate ID is in long form,
					// we pass `allowRef = true`.
					if err := outBuilderID.Matches(*bid, true); err != nil {
						t.Errorf(fmt.Sprintf("matches failed (2): %v", err))
					}
				}
			}
		})
	}
}

func Test_runVerifyGHAArtifactImage(t *testing.T) {
	t.Parallel()

	// Override cosign image verification function for local image testing.
	container.RunCosignImageVerification = func(ctx context.Context,
		image string, co *cosign.CheckOpts,
	) ([]oci.Signature, bool, error) {
		key := "@sha256:"
		i := strings.Index(image, key)
		if i < 0 {
			return nil, false, fmt.Errorf("cannot find '%v' in '%v'", key, image)
		}
		image = image[:i]
		return cosign.VerifyLocalImageAttestations(ctx, image, co)
	}

	builder := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml"
	tests := []struct {
		name         string
		artifact     string
		source       string
		pbranch      *string
		ptag         *string
		pversiontag  *string
		pBuilderID   *string
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
			pBuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/not-trusted.yml"),
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

			checkVersions := getBuildersAndVersions(t, "", nil, GHA_ARTIFACT_IMAGE_BUILDERS)
			if tt.noversion {
				checkVersions = []string{""}
			}

			for _, v := range checkVersions {
				image := filepath.Clean(filepath.Join(TEST_DIR, v, tt.artifact))
				// TODO(#258): test for tagged builder.
				sv := path.Base(v)
				// For each test, we run 2 sub-tests:
				//	1. With the the full builderID including the semver in short form.
				//	2. With the the full builderID including the semver in long form.
				//	3. With only the name of the builder.
				//	4. With no builder ID.
				builderIDs := []*string{
					pString(builder + "@" + sv),
					pString(builder + "@refs/tags/" + sv),
					pString(builder),
					nil,
				}

				// If builder ID is set, use it.
				if tt.pBuilderID != nil {
					builderIDs = []*string{tt.pBuilderID}
				}

				// Compute the digest and append it to the image so that's it 'immutable'.
				digest, err := localDigestCompute(image)
				if err != nil {
					panic(fmt.Sprintf("digest computation %v", err))
				}
				image = fmt.Sprintf("%v@sha256:%v", image, digest)

				for _, bid := range builderIDs {
					cmd := verify.VerifyImageCommand{
						SourceURI:        tt.source,
						SourceBranch:     tt.pbranch,
						BuilderID:        bid,
						SourceTag:        tt.ptag,
						SourceVersionTag: tt.pversiontag,
					}

					outBuilderID, err := cmd.Exec(context.Background(), []string{image})
					if !errCmp(err, tt.err) {
						t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
					}

					if err != nil {
						continue
					}

					// Validate against test's expected builderID, if provided.
					if tt.outBuilderID != "" {
						if err := outBuilderID.Matches(tt.outBuilderID, false); err != nil {
							t.Errorf(fmt.Sprintf("matches failed: %v", err))
						}
					}

					if bid == nil {
						continue
					}

					// If we have a generated a user-provided bid, then validate it against the
					// resulting builderID returned by the provenance check.
					// Since this a GHA and the certificate ID is in long form,
					// we pass `allowRef = true`.
					if err := outBuilderID.Matches(*bid, true); err != nil {
						t.Errorf(fmt.Sprintf("matches failed: %v", err))
					}
				}
			}
		})
	}
}

func localDigestCompute(image string) (string, error) {
	filename := image + ".digest"
	digest, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("ReadFile fail: %w", err)
	}
	return strings.TrimPrefix(string(digest), "sha256:"), nil
}

func Test_runVerifyGCBArtifactImage(t *testing.T) {
	t.Parallel()
	builder := "https://cloudbuild.googleapis.com/GoogleHostedWorker"
	tests := []struct {
		name           string
		artifact       string
		artifactDigest map[string]string
		noDigest       bool
		remote         bool
		provenance     string
		source         string
		ptag           *string
		pversiontag    *string
		pBuilderID     *string
		outBuilderID   string
		err            error
		// noversion is a special case where we are not testing all builder versions
		// for example, testdata for the builder at head in trusted repo workflows
		// or testdata from malicious untrusted builders.
		// When true, this does not iterate over all builder versions.
		noversion bool
		// minversion is a special case to test a newly added feature into a builder
		minversion string
	}{
		{
			name:       "valid main branch default",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-github.json",
			source:     "github.com/laurentsimon/gcb-tests",
		},
		{
			name:       "valid main branch gcs",
			artifact:   "gcloud-container-gcs",
			provenance: "gcloud-container-gcs.json",
			minversion: "v0.3",
			source:     "gs://slsa-tooling_cloudbuild/source/1663616632.078353-fc7db143dcc64b5f9fe71d0497125ca1.tgz",
		},
		{
			name:       "mismatch input builder version",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-github.json",
			source:     "github.com/laurentsimon/gcb-tests",
			pBuilderID: pString(builder + "@v0.4"),
			err:        serrors.ErrorMismatchBuilderID,
		},
		{
			name:       "unsupported builder",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-github.json",
			source:     "github.com/laurentsimon/gcb-tests",
			pBuilderID: pString(builder + "a"),
			err:        serrors.ErrorVerifierNotSupported,
		},
		{
			name:         "match output builder name",
			artifact:     "gcloud-container-github",
			provenance:   "gcloud-container-github.json",
			source:       "github.com/laurentsimon/gcb-tests",
			outBuilderID: builder,
		},
		{
			name:       "invalid repo name",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-github.json",
			source:     "github.com/laurentsimon/name",
			err:        serrors.ErrorMismatchSource,
		},
		{
			name:       "invalie org name",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-github.json",
			source:     "github.com/org/gcb-tests",
			err:        serrors.ErrorMismatchSource,
		},
		{
			name:       "invalid cloud git",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-github.json",
			source:     "gitlab.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorMismatchSource,
		},
		{
			name:       "invalid payload digest",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-mismatch-payload-digest.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorNoValidSignature,
		},
		{
			name:       "invalid payload builderid",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-mismatch-payload-builderid.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorNoValidSignature,
		},
		{
			name:       "invalid summary digest",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-mismatch-summary-digest.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorMismatchHash,
		},
		{
			name:       "invalid text digest",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-mismatch-text-digest.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorMismatchIntoto,
		},
		{
			name:       "invalid text build steps",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-mismatch-text-steps.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorMismatchIntoto,
		},
		{
			name:       "invalid metadata kind",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-mismatch-metadata-kind.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorInvalidFormat,
		},
		{
			name:       "invalid metadata resourceUri sha256",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-mismatch-metadata-urisha256.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorMismatchHash,
		},
		{
			name:       "invalid signature encoding",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-invalid-signature-encoding.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorNoValidSignature,
		},
		{
			name:       "invalid signature empty",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-empty-signature.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorNoValidSignature,
		},
		{
			name:       "invalid signature none",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-no-signature.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorInvalidDssePayload,
		},
		{
			name:       "invalid region",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-invalid-signature-region.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorNoValidSignature,
		},
		{
			name:       "invalid empty region",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-empty-signature-region.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorNoValidSignature,
		},
		{
			name:       "invalid keyid",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-invalid-keyid.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorNoValidSignature,
		},
		{
			name:       "invalid keyid empty",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-empty-keyid.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorNoValidSignature,
		},
		{
			name:       "invalid keyid none",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-no-keyid.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorNoValidSignature,
		},
		{
			name:       "invalid signature multiple",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-multiple-invalid-signatures.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorNoValidSignature,
		},
		{
			name:       "signature multiple 2nd valid",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-multiple-signatures-2ndvalid.json",
			source:     "github.com/laurentsimon/gcb-tests",
		},
		{
			name:       "signature multiple 3rd valid",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-multiple-signatures-3rdvalid.json",
			source:     "github.com/laurentsimon/gcb-tests",
		},
		{
			name:       "invalid multiple provenance",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-multiple-invalid-provenance.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorNoValidSignature,
		},
		{
			name:       "tag match",
			artifact:   "gcloud-container-github-tag",
			provenance: "gcloud-container-github-tag.json",
			source:     "github.com/slsa-framework/example-package",
			ptag:       pString("v33.0.4"),
			minversion: "v0.3",
		},
		{
			name:       "tag mismatch major",
			artifact:   "gcloud-container-github-tag",
			provenance: "gcloud-container-github-tag.json",
			source:     "github.com/slsa-framework/example-package",
			ptag:       pString("v34.0.4"),
			minversion: "v0.3",
			err:        serrors.ErrorMismatchTag,
		},
		{
			name:       "tag mismatch minor",
			artifact:   "gcloud-container-github-tag",
			provenance: "gcloud-container-github-tag.json",
			source:     "github.com/slsa-framework/example-package",
			ptag:       pString("v33.1.4"),
			minversion: "v0.3",
			err:        serrors.ErrorMismatchTag,
		},
		{
			name:       "tag mismatch patch",
			artifact:   "gcloud-container-github-tag",
			provenance: "gcloud-container-github-tag.json",
			source:     "github.com/slsa-framework/example-package",
			ptag:       pString("v33.0.5"),
			minversion: "v0.3",
			err:        serrors.ErrorMismatchTag,
		},
		{
			name:        "versioned tag match major",
			artifact:    "gcloud-container-github-tag",
			provenance:  "gcloud-container-github-tag.json",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v33"),
			minversion:  "v0.3",
		},
		{
			name:        "versioned tag match minor",
			artifact:    "gcloud-container-github-tag",
			provenance:  "gcloud-container-github-tag.json",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v33.0"),
			minversion:  "v0.3",
		},
		{
			name:        "versioned tag match patch",
			artifact:    "gcloud-container-github-tag",
			provenance:  "gcloud-container-github-tag.json",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v33.0.4"),
			minversion:  "v0.3",
		},
		{
			name:        "versioned tag mismatch patch",
			artifact:    "gcloud-container-github-tag",
			provenance:  "gcloud-container-github-tag.json",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v33.0.5"),
			minversion:  "v0.3",
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned tag mismatch minor",
			artifact:    "gcloud-container-github-tag",
			provenance:  "gcloud-container-github-tag.json",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v33.1"),
			minversion:  "v0.3",
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned tag mismatch major",
			artifact:    "gcloud-container-github-tag",
			provenance:  "gcloud-container-github-tag.json",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v35"),
			minversion:  "v0.3",
			err:         serrors.ErrorMismatchVersionedTag,
		},
		// TODO(388): verify the correct provenance is returned.
		// This should also be done for all other entries in this test.
		{
			name:       "multiple provenance 2nd valid",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-multiple-provenance-2ndvalid.json",
			source:     "github.com/laurentsimon/gcb-tests",
		},
		{
			name:       "multiple provenance 3rd valid",
			artifact:   "gcloud-container-github",
			provenance: "gcloud-container-multiple-provenance-3rdvalid.json",
			source:     "github.com/laurentsimon/gcb-tests",
		},
		{
			name: "oci valid with tag",
			// Image re-tagged and pushed to docker hub. This image is public.
			artifact: "laurentsimon/slsa-gcb-%s:test",
			artifactDigest: map[string]string{
				"v0.2": "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
				"v0.3": "f472ca4b68898c951ac3b476cba919d0d56fca4ced631fabcead51e4b2b690e7",
			},
			remote:     true,
			source:     "github.com/laurentsimon/gcb-tests",
			provenance: "gcloud-container-github.json",
		},
		{
			name:     "oci mismatch digest",
			artifact: "index.docker.io/laurentsimon/scorecard",
			artifactDigest: map[string]string{
				"v0.2": "d794817bdf9c7e5ec34758beb90a18113c7dfbd737e760cabf8dd923d49e96f4",
				"v0.3": "d794817bdf9c7e5ec34758beb90a18113c7dfbd737e760cabf8dd923d49e96f4",
			},
			remote:     true,
			provenance: "gcloud-container-github.json",
			source:     "github.com/laurentsimon/gcb-tests",
			err:        serrors.ErrorMismatchHash,
		},
		{
			name:     "oci valid no tag",
			artifact: "laurentsimon/slsa-gcb-%s",
			artifactDigest: map[string]string{
				"v0.2": "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
				"v0.3": "f472ca4b68898c951ac3b476cba919d0d56fca4ced631fabcead51e4b2b690e7",
			},
			remote:     true,
			source:     "github.com/laurentsimon/gcb-tests",
			provenance: "gcloud-container-github.json",
		},
		// No version.
		{
			name:       "oci is mutable",
			artifact:   "index.docker.io/laurentsimon/scorecard",
			noversion:  true,
			remote:     true,
			noDigest:   true,
			source:     "github.com/laurentsimon/gcb-tests",
			provenance: "gcloud-container-github.json",
			pBuilderID: pString(builder + "@v0.2"),
			err:        serrors.ErrorMutableImage,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkVersions := getBuildersAndVersions(t, tt.minversion, nil, GCB_ARTIFACT_IMAGE_BUILDERS)
			if tt.noversion {
				checkVersions = []string{""}
			}

			for _, v := range checkVersions {
				semver := path.Base(v)
				// For each test, we run 2 sub-tests:
				// 	1. With the the full builderID including the semver.
				//	2. With only the name of the builder.
				builderIDs := []string{builder + "@" + semver, builder}
				provenance := filepath.Clean(filepath.Join(TEST_DIR, v, tt.provenance))
				image := tt.artifact
				digestFn := container.GetImageDigest

				// If builder ID is set, use it.
				if tt.pBuilderID != nil {
					builderIDs = []string{*tt.pBuilderID}
				}

				// Select the right image according to the builder version we are testing.
				if strings.Contains(image, `%s`) {
					image = fmt.Sprintf(image, semver)
				}
				// Add the sha256 digest to the image name, if provided.
				if len(tt.artifactDigest) > 0 {
					digest, ok := tt.artifactDigest[semver]
					if !ok {
						panic(fmt.Sprintf("%s not present in artifactDigest %v", semver, tt.artifactDigest))
					}
					image = fmt.Sprintf("%s@sha256:%s", image, digest)
				}

				// If it is a local image, change the digest computation.
				if !tt.remote {
					image = filepath.Clean(filepath.Join(TEST_DIR, v, image))
					digestFn = localDigestCompute
				}

				if len(tt.artifactDigest) == 0 && !tt.noDigest {
					// Compute the digest and append it to the image so that's it 'immutable'.
					digest, err := digestFn(image)
					if err != nil {
						panic(fmt.Sprintf("digest computation %v", err))
					}
					image = fmt.Sprintf("%v@sha256:%v", image, digest)
				}

				// We run the test for each builderID, in order to test
				// a builderID provided by name and one containing both the name
				// and semver.
				for _, bid := range builderIDs {
					cmd := verify.VerifyImageCommand{
						SourceURI:        tt.source,
						SourceBranch:     nil,
						BuilderID:        &bid,
						SourceTag:        tt.ptag,
						SourceVersionTag: tt.pversiontag,
						ProvenancePath:   &provenance,
					}

					outBuilderID, err := cmd.Exec(context.Background(), []string{image})

					if !errCmp(err, tt.err) {
						t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
					}

					if err != nil {
						return
					}

					// Validate against test's expected builderID, if provided.
					if tt.outBuilderID != "" {
						if err := outBuilderID.Matches(tt.outBuilderID, false); err != nil {
							t.Errorf(fmt.Sprintf("matches failed: %v", err))
						}
					}

					// Validate against builderID we generated automatically.
					if err := outBuilderID.Matches(bid, false); err != nil {
						t.Errorf(fmt.Sprintf("matches failed: %v", err))
					}
				}
			}
		})
	}
}

// TODO(https://github.com/slsa-framework/slsa-verifier/issues/485): Version the test-cases
// when a version for the builder is released.
func Test_runVerifyGHADockerBased(t *testing.T) {
	// We cannot use t.Setenv due to parallelized tests.
	os.Setenv("SLSA_VERIFIER_EXPERIMENTAL", "1")
	os.Setenv("SLSA_VERIFIER_TESTING", "1")

	t.Parallel()

	builder := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_docker-based_slsa3.yml"
	tests := []struct {
		name        string
		artifacts   []string
		source      string
		pbranch     *string
		ptag        *string
		pversiontag *string
		pBuilderID  *string
		inputs      map[string]string
		err         error
	}{
		{
			name:       "valid main branch default",
			artifacts:  []string{"workflow_dispatch.main.default"},
			source:     "github.com/slsa-framework/example-package",
			pBuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_docker-based_slsa3.yml"),
		},
		{
			name:       "valid main branch default - invalid builderID",
			artifacts:  []string{"workflow_dispatch.main.default"},
			source:     "github.com/slsa-framework/example-package",
			pBuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/not-trusted.yml"),
			err:        serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name:       "valid main branch set",
			artifacts:  []string{"workflow_dispatch.main.default"},
			source:     "github.com/slsa-framework/example-package",
			pBuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_docker-based_slsa3.yml"),
			pbranch:    pString("main"),
		},

		{
			name:       "wrong branch master",
			artifacts:  []string{"workflow_dispatch.main.default"},
			source:     "github.com/slsa-framework/example-package",
			pbranch:    pString("master"),
			pBuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_docker-based_slsa3.yml"),
			err:        serrors.ErrorMismatchBranch,
		},
		{
			name:       "wrong source append A",
			artifacts:  []string{"workflow_dispatch.main.default"},
			source:     "github.com/slsa-framework/example-packageA",
			pBuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_docker-based_slsa3.yml"),
			err:        serrors.ErrorMismatchSource,
		},
		{
			name:       "wrong source prepend A",
			artifacts:  []string{"workflow_dispatch.main.default"},
			source:     "Agithub.com/slsa-framework/example-package",
			pBuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_docker-based_slsa3.yml"),
			err:        serrors.ErrorMismatchSource,
		},
		{
			name:       "wrong source middle A",
			artifacts:  []string{"workflow_dispatch.main.default"},
			source:     "github.com/Aslsa-framework/example-package",
			pBuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_docker-based_slsa3.yml"),
			err:        serrors.ErrorMismatchSource,
		},
		{
			name:       "tag no match empty tag workflow_dispatch",
			artifacts:  []string{"workflow_dispatch.main.default"},
			source:     "github.com/slsa-framework/example-package",
			pBuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_docker-based_slsa3.yml"),
			ptag:       pString("v1.2.3"),
			err:        serrors.ErrorMismatchTag,
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch",
			artifacts:   []string{"workflow_dispatch.main.default"},
			source:      "github.com/slsa-framework/example-package",
			pBuilderID:  pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_docker-based_slsa3.yml"),
			pversiontag: pString("v1"),
			err:         serrors.ErrorInvalidSemver,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkVersions := getBuildersAndVersions(t, "", nil, GHA_ARTIFACT_DOCKER_BUILDERS)

			for _, v := range checkVersions {
				testPath := filepath.Clean(filepath.Join(TEST_DIR, v, tt.artifacts[0]))
				provenancePath := fmt.Sprintf("%s.intoto.sigstore", testPath)

				artifacts := make([]string, len(tt.artifacts))
				for i, artifact := range tt.artifacts {
					artifacts[i] = filepath.Clean(filepath.Join(TEST_DIR, v, artifact))
				}

				// For each test, we run 2 sub-tests:
				//	1. With the the full builderID including the semver in short form.
				//	2. With the the full builderID including the semver in long form.
				//	3. With only the name of the builder.
				//	4. With no builder ID.
				sv := path.Base(v)
				builderIDs := []*string{
					pString(builder + "@" + sv),
					pString(builder + "@refs/tags/" + sv),
					pString(builder),
					nil,
				}

				// If builder ID is set, use it.
				if tt.pBuilderID != nil {
					builderIDs = []*string{tt.pBuilderID}
				}

				for _, bid := range builderIDs {
					cmd := verify.VerifyArtifactCommand{
						ProvenancePath:      provenancePath,
						SourceURI:           tt.source,
						SourceBranch:        tt.pbranch,
						BuilderID:           bid,
						SourceTag:           tt.ptag,
						SourceVersionTag:    tt.pversiontag,
						BuildWorkflowInputs: tt.inputs,
					}

					// The outBuilderID is the actual builder ID from the provenance.
					// This is always long form for the GHA builders.
					_, err := cmd.Exec(context.Background(), artifacts)
					if !errCmp(err, tt.err) {
						t.Errorf("%v: %v", v, cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
					}
				}
			}
		})
	}
}
