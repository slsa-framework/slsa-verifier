//go:build regression

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/semver"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"

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
	GHA_ARTIFACT_PATH_BUILDERS = []string{"gha_go", "gha_generic", "gha_delegator", "gha_maven", "gha_gradle"}
	// TODO(https://github.com/slsa-framework/slsa-verifier/issues/485): Merge this with
	// GHA_ARTIFACT_PATH_BUILDERS.
	GHA_ARTIFACT_CONTAINER_BUILDERS = []string{"gha_container-based"}
	GHA_ARTIFACT_IMAGE_BUILDERS     = []string{"gha_generic_container"}
	GCB_ARTIFACT_IMAGE_BUILDERS     = []string{"gcb_container"}
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
	// We cannot use t.Setenv due to parallelized tests.
	// TODO(639): Remove this by regenerating multiple subjects test.
	os.Setenv("SLSA_VERIFIER_TESTING", "1")

	t.Parallel()
	goBuilder := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml"
	genericBuilder := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"
	delegatorBuilder := "https://github.com/slsa-framework/example-trw/.github/workflows/builder_high-perms_slsa3.yml"
	mavenBuilder := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_maven_slsa3.yml"
	gradleBuilder := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_gradle_slsa3.yml"

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
			err:       serrors.ErrorInvalidRef,
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch",
			artifacts:   []string{"binary-linux-amd64-workflow_dispatch"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v1"),
			err:         serrors.ErrorInvalidRef,
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
			err:         serrors.ErrorInvalidRef,
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
		t.Run(tt.name, func(t *testing.T) {
			// Avoid rate limiting by not running the tests in parallel.
			// t.Parallel()
			checkVersions := getBuildersAndVersions(t, "v1.2.2", tt.builders, GHA_ARTIFACT_PATH_BUILDERS)
			if tt.noversion {
				checkVersions = []string{""}
			}

			for _, v := range checkVersions {
				var provenancePath string
				var byob bool
				if tt.provenancePath == "" {
					testPath := filepath.Clean(filepath.Join(TEST_DIR, v, tt.artifacts[0]))
					if strings.Contains(testPath, "delegator") || strings.Contains(testPath, "maven") || strings.Contains(testPath, "gradle") {
						provenancePath = fmt.Sprintf("%s.build.slsa", testPath)
						byob = true
					} else {
						provenancePath = fmt.Sprintf("%s.intoto.jsonl", testPath)
					}
				} else {
					provenancePath = filepath.Clean(filepath.Join(TEST_DIR, v, tt.provenancePath))
				}

				artifacts := make([]string, len(tt.artifacts))
				for i, artifact := range tt.artifacts {
					artifacts[i] = filepath.Clean(filepath.Join(TEST_DIR, v, artifact))
				}

				// TODO(#258): invalid builder ref.
				sv := filepath.Base(v)
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
				case strings.HasSuffix(name, "_delegator"):
					builder = delegatorBuilder
				case strings.HasSuffix(name, "_maven"):
					builder = mavenBuilder
				case strings.HasSuffix(name, "_gradle"):
					builder = gradleBuilder
				default:
					builder = genericBuilder
				}

				// Default builders to test.
				builderIDs := []*string{
					pString(builder),
				}

				// Do not run without explicit builder ID for the delegator,
				// because it's hosted on a different repo slsa-framework/example-package.
				if builder != delegatorBuilder {
					builderIDs = append(builderIDs, nil)
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

					// BYOB-based builders ignore the reusable workflow.
					if errCmp(tt.err, serrors.ErrorUntrustedReusableWorkflow) && byob {
						tt.err = serrors.ErrorMismatchBuilderID
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
						if err := outBuilderID.MatchesLoose(tt.outBuilderID, false); err != nil {
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
					if err := outBuilderID.MatchesLoose(*bid, true); err != nil {
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
		// minversion is a special case to test a newly added feature into a builder.
		minversion string
		// maxversion is a special case to handle incompatible error changes in the builder.
		maxversion string
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
			name:       "tag no match empty tag workflow_dispatch",
			artifact:   "container_workflow_dispatch",
			source:     "github.com/slsa-framework/example-package",
			ptag:       pString("v1.2.3"),
			maxversion: "v1.8.0",
			err:        serrors.ErrorInvalidRef,
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch",
			artifact:    "container_workflow_dispatch",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v1"),
			maxversion:  "v1.8.0",
			err:         serrors.ErrorInvalidRef,
		},
		{
			name:       "tag no match empty tag workflow_dispatch > v1.9.0, <= v2.0.0",
			artifact:   "container_workflow_dispatch",
			source:     "github.com/slsa-framework/example-package",
			ptag:       pString("v1.2.3"),
			minversion: "v1.9.0",
			maxversion: "v2.0.0",
			err:        serrors.ErrorMismatchTag,
		},
		{
			name:       "tag no match empty tag workflow_dispatch > v2.0.0",
			artifact:   "container_workflow_dispatch",
			source:     "github.com/slsa-framework/example-package",
			ptag:       pString("v1.2.3"),
			minversion: "v2.0.0",
			err:        serrors.ErrorInvalidRef,
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch > v1.9.0, <= v2.0.0",
			artifact:    "container_workflow_dispatch",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v1"),
			minversion:  "v1.9.0",
			maxversion:  "v2.0.0",
			err:         serrors.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch > v2.0.0",
			artifact:    "container_workflow_dispatch",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v1"),
			minversion:  "v2.0.0",
			err:         serrors.ErrorInvalidRef,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkVersions := getBuildersAndVersions(t, "", nil, GHA_ARTIFACT_IMAGE_BUILDERS)
			if tt.noversion {
				checkVersions = []string{""}
			}

			for _, v := range checkVersions {
				parts := strings.Split(v, "/")
				version := ""
				if len(parts) > 1 {
					version = parts[1]
				}
				if version != "" && tt.minversion != "" && semver.Compare(version, tt.minversion) <= 0 {
					fmt.Println("skiping due to min:", version)
					continue
				}
				if version != "" && tt.maxversion != "" && semver.Compare(version, tt.maxversion) > 0 {
					fmt.Println("skiping due to max:", version)
					continue
				}
				image := filepath.Clean(filepath.Join(TEST_DIR, v, tt.artifact))
				// TODO(#258): test for tagged builder.
				sv := filepath.Base(v)
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
						t.Error(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
					}

					if err != nil {
						continue
					}

					// Validate against test's expected builderID, if provided.
					if tt.outBuilderID != "" {
						if err := outBuilderID.MatchesLoose(tt.outBuilderID, false); err != nil {
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
					if err := outBuilderID.MatchesLoose(*bid, true); err != nil {
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkVersions := getBuildersAndVersions(t, tt.minversion, nil, GCB_ARTIFACT_IMAGE_BUILDERS)
			if tt.noversion {
				checkVersions = []string{""}
			}

			for _, v := range checkVersions {
				semver := filepath.Base(v)
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
						t.Error(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
					}

					if err != nil {
						return
					}

					// Validate against test's expected builderID, if provided.
					if tt.outBuilderID != "" {
						if err := outBuilderID.MatchesLoose(tt.outBuilderID, false); err != nil {
							t.Errorf(fmt.Sprintf("matches failed: %v", err))
						}
					}

					// Validate against builderID we generated automatically.
					if err := outBuilderID.MatchesLoose(bid, false); err != nil {
						t.Errorf(fmt.Sprintf("matches failed: %v", err))
					}
				}
			}
		})
	}
}

func Test_runVerifyGHAContainerBased(t *testing.T) {
	t.Parallel()

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
			name:      "valid main branch default",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/slsa-framework/example-package",
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch",
			artifacts:   []string{"binary-linux-amd64-workflow_dispatch"},
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v1"),
			err:         serrors.ErrorInvalidRef,
		},
		{
			name:      "tag no match empty tag workflow_dispatch",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/slsa-framework/example-package",
			ptag:      pString("v1.2.3"),
			err:       serrors.ErrorInvalidRef,
		},
		{
			name:      "wrong branch master",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/slsa-framework/example-package",
			pbranch:   pString("master"),
			err:       serrors.ErrorMismatchBranch,
		},
		{
			name:      "valid main branch set",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/slsa-framework/example-package",
			pbranch:   pString("main"),
		},
		{
			name:       "valid main branch default - invalid builderID",
			artifacts:  []string{"binary-linux-amd64-workflow_dispatch"},
			source:     "github.com/slsa-framework/example-package",
			pBuilderID: pString("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/not-trusted.yml"),
			err:        serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name:      "wrong source append A",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/slsa-framework/example-packageA",
			err:       serrors.ErrorMismatchSource,
		},
		{
			name:      "wrong source prepend A",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "Agithub.com/slsa-framework/example-package",
			err:       serrors.ErrorMismatchSource,
		},
		{
			name:      "wrong source middle A",
			artifacts: []string{"binary-linux-amd64-workflow_dispatch"},
			source:    "github.com/Aslsa-framework/example-package",
			err:       serrors.ErrorMismatchSource,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkVersions := getBuildersAndVersions(t, "", nil, GHA_ARTIFACT_CONTAINER_BUILDERS)

			for _, v := range checkVersions {
				testPath := filepath.Clean(filepath.Join(TEST_DIR, v, tt.artifacts[0]))
				sv := filepath.Base(v)
				var provenancePath string
				if semver.Compare(sv, "v1.8.0") >= 0 {
					provenancePath = fmt.Sprintf("%s.intoto.build.slsa", testPath)
				} else {
					provenancePath = fmt.Sprintf("%s.intoto.sigstore", testPath)
				}

				artifacts := make([]string, len(tt.artifacts))
				for i, artifact := range tt.artifacts {
					artifacts[i] = filepath.Clean(filepath.Join(TEST_DIR, v, artifact))
				}

				// For each test, we run 2 sub-tests:
				//	1. With the the full builderID including the semver in short form.
				//	2. With the the full builderID including the semver in long form.
				//	3. With only the name of the builder.
				//	4. With no builder ID.
				builder := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_container-based_slsa3.yml"

				refName := "@refs/tags/"
				builderIDs := []*string{
					pString(builder + refName + sv),
					pString(builder),
					pString(builder + "@" + sv),
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

func Test_runVerifyGithubAttestation(t *testing.T) {
	t.Parallel()
	os.Setenv("SLSA_VERIFIER_EXPERIMENTAL", "1")

	bcrReleaserBuilderID := "https://github.com/bazel-contrib/.github/.github/workflows/release_ruleset.yaml"
	bcrPublisherBuilderID := "https://github.com/bazel-contrib/publish-to-bcr/.github/workflows/publish.yaml"

	tests := []struct {
		name      string
		artifact  string
		source    string
		builderID string
		err       error
	}{
		{
			name:      "module.bazel using publishing builder",
			artifact:  "MODULE.bazel",
			source:    "github.com/aspect-build/rules_lint",
			builderID: bcrPublisherBuilderID,
		},
		{
			name:      "source archive using release builder",
			artifact:  "rules_lint-v1.3.1.tar.gz",
			source:    "github.com/aspect-build/rules_lint",
			builderID: bcrReleaserBuilderID,
		},
		{
			name:      "module.bazel wrong signer",
			artifact:  "MODULE-wrong-signer.bazel",
			source:    "github.com/aspect-build/rules_lint",
			builderID: bcrPublisherBuilderID,
			err:       serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name:     "module.bazel no builder id",
			artifact: "MODULE.bazel",
			source:   "github.com/aspect-build/rules_lint",
			err:      serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name:     "source archive no builder id",
			artifact: "rules_lint-v1.3.1.tar.gz",
			source:   "github.com/aspect-build/rules_lint",
			err:      serrors.ErrorUntrustedReusableWorkflow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			artifactPath := filepath.Clean(filepath.Join(TEST_DIR, "bcr", tt.artifact))
			// we treat these single entry *.intoto.jsonl bundles as single attestations
			attestationPath := fmt.Sprintf("%s.intoto.jsonl", artifactPath)
			cmd := verify.VerifyGithubAttestationCommand{
				AttestationPath: attestationPath,
				BuilderID:       &tt.builderID,
				SourceURI:       tt.source,
			}

			_, err := cmd.Exec(context.Background(), artifactPath)
			if !errCmp(tt.err, err) {
				t.Errorf("unexpected error (-want +got):\n%s", cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
			}
		})
	}

}

func Test_runVerifyNpmPackage(t *testing.T) {
	// We cannot use t.Setenv due to parallelized tests.
	os.Setenv("SLSA_VERIFIER_EXPERIMENTAL", "1")
	t.Parallel()

	tests := []struct {
		name       string
		artifact   string
		builderID  *string
		source     string
		pkgVersion *string
		pkgName    *string
		err        error
	}{
		// npm CLI with tag.
		{
			name:       "valid npm CLI builder",
			artifact:   "supreme-googles-cli-v02-tag.tgz",
			source:     "github.com/trishankatdatadog/supreme-goggles",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@trishankatdatadog/supreme-goggles"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:       "valid npm CLI builder v1",
			artifact:   "gundam-visor-cli-v1-tag.tgz",
			source:     "github.com/ramonpetgrave64/gundam-visor",
			pkgVersion: pointerTo("1.0.1"),
			pkgName:    pointerTo("gundam-visor"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:       "valid npm CLI builder short runner name",
			artifact:   "supreme-googles-cli-v02-tag.tgz",
			source:     "github.com/trishankatdatadog/supreme-goggles",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@trishankatdatadog/supreme-goggles"),
			builderID:  pointerTo("https://github.com/actions/runner"),
		},
		{
			// The builderID for v1 should never be the "shortname".
			// https://github.com/npm/cli/blob/93883bb6459208a916584cad8c6c72a315cf32af/workspaces/libnpmpublish/lib/provenance.js#L58.
			name:       "valid npm CLI builder v1 short runner name",
			artifact:   "gundam-visor-cli-v1-tag.tgz",
			source:     "github.com/ramonpetgrave64/gundam-visor",
			pkgVersion: pointerTo("1.0.1"),
			pkgName:    pointerTo("gundam-visor"),
			builderID:  pointerTo("https://github.com/actions/runner"),
			err:        serrors.ErrorInvalidBuilderID,
		},
		{
			name:       "valid npm CLI builder no builder",
			artifact:   "supreme-googles-cli-v02-tag.tgz",
			source:     "github.com/trishankatdatadog/supreme-goggles",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@trishankatdatadog/supreme-goggles"),
			err:        serrors.ErrorInvalidBuilderID,
		},
		{
			name:       "valid npm CLI builder v1 no builder",
			artifact:   "gundam-visor-cli-v1-tag.tgz",
			source:     "github.com/ramonpetgrave64/gundam-visor",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("gundam-visor"),
			err:        serrors.ErrorInvalidBuilderID,
		},
		{
			name:       "valid npm CLI builder mismatch builder",
			artifact:   "supreme-googles-cli-v02-tag.tgz",
			source:     "github.com/trishankatdatadog/supreme-goggles",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@trishankatdatadog/supreme-goggles"),
			builderID:  pointerTo("https://github.com/actions/runner2"),
			err:        serrors.ErrorNotSupported,
		},
		{
			name:       "valid npm CLI builder v1 mismatch builder",
			artifact:   "gundam-visor-cli-v1-tag.tgz",
			source:     "github.com/ramonpetgrave64/gundam-visor",
			pkgVersion: pointerTo("1.0.1"),
			pkgName:    pointerTo("gundam-visor"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted2"),
			err:        serrors.ErrorNotSupported,
		},
		{
			name:       "valid npm CLI builder no package name",
			artifact:   "supreme-googles-cli-v02-tag.tgz",
			source:     "github.com/trishankatdatadog/supreme-goggles",
			pkgVersion: pointerTo("1.0.5"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:       "valid npm CLI builder v1 no package name",
			artifact:   "gundam-visor-cli-v1-tag.tgz",
			source:     "github.com/ramonpetgrave64/gundam-visor",
			pkgVersion: pointerTo("1.0.1"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:      "valid npm CLI builder no package version",
			artifact:  "supreme-googles-cli-v02-tag.tgz",
			source:    "github.com/trishankatdatadog/supreme-goggles",
			pkgName:   pointerTo("@trishankatdatadog/supreme-goggles"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:      "valid npm CLI builder v1 no package version",
			artifact:  "gundam-visor-cli-v1-tag.tgz",
			source:    "github.com/ramonpetgrave64/gundam-visor",
			pkgName:   pointerTo("gundam-visor"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:       "valid npm CLI builder mismatch source",
			artifact:   "supreme-googles-cli-v02-tag.tgz",
			source:     "github.com/trishankatdatadog/supreme-goggleS",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@trishankatdatadog/supreme-goggles"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
			err:        serrors.ErrorMismatchSource,
		},
		{
			name:       "valid npm CLI builder v1 mismatch source",
			artifact:   "gundam-visor-cli-v1-tag.tgz",
			source:     "github.com/ramonpetgrave64/gundam-visorS",
			pkgVersion: pointerTo("1.0.1"),
			pkgName:    pointerTo("gundam-visor"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
			err:        serrors.ErrorMismatchSource,
		},
		{
			name:       "valid npm CLI builder mismatch package version",
			artifact:   "supreme-googles-cli-v02-tag.tgz",
			source:     "github.com/trishankatdatadog/supreme-goggles",
			pkgVersion: pointerTo("1.0.4"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
			err:        serrors.ErrorMismatchPackageVersion,
		},
		{
			name:       "valid npm CLI builder v1 mismatch package version",
			artifact:   "gundam-visor-cli-v1-tag.tgz",
			source:     "github.com/ramonpetgrave64/gundam-visor",
			pkgVersion: pointerTo("1.0.2"),
			pkgName:    pointerTo("gundam-visor"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
			err:        serrors.ErrorMismatchPackageVersion,
		},
		{
			name:      "valid npm CLI builder mismatch package name",
			artifact:  "supreme-googles-cli-v02-tag.tgz",
			source:    "github.com/trishankatdatadog/supreme-goggles",
			pkgName:   pointerTo("@trishankatdatadog/supreme-goggleS"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
			err:       serrors.ErrorMismatchPackageName,
		},
		{
			name:       "valid npm CLI builder v1 mismatch package name",
			artifact:   "gundam-visor-cli-v1-tag.tgz",
			source:     "github.com/ramonpetgrave64/gundam-visor",
			pkgVersion: pointerTo("1.0.1"),
			pkgName:    pointerTo("gundam-visorS"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
			err:        serrors.ErrorMismatchPackageName,
		},
		{
			name:      "invalid signature provenance npm CLI",
			artifact:  "supreme-googles-cli-v02-tag-invalidsigprov.tgz",
			source:    "github.com/trishankatdatadog/supreme-goggles",
			pkgName:   pointerTo("@trishankatdatadog/supreme-goggles"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
			err:       serrors.ErrorInvalidSignature,
		},
		{
			name:       "invalid signature provenance npm CLI v1",
			artifact:   "gundam-visor-cli-v1-tag-invalidsigprov.tgz",
			source:     "github.com/ramonpetgrave64/gundam-visor",
			pkgVersion: pointerTo("1.0.1"),
			pkgName:    pointerTo("gundam-visor"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
			err:        serrors.ErrorInvalidSignature,
		},
		{
			name:      "invalid signature publish npm CLI",
			artifact:  "supreme-googles-cli-v02-tag-invalidsigpub.tgz",
			source:    "github.com/trishankatdatadog/supreme-goggles",
			pkgName:   pointerTo("@trishankatdatadog/supreme-goggles"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
			err:       serrors.ErrorInvalidSignature,
		},
		{
			name:       "invalid signature publish npm CLI v1",
			artifact:   "gundam-visor-cli-v1-tag-invalidsigpub.tgz",
			source:     "github.com/ramonpetgrave64/gundam-visor",
			pkgVersion: pointerTo("1.0.1"),
			pkgName:    pointerTo("gundam-visor"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
			err:        serrors.ErrorInvalidSignature,
		},
		// npm CLI with main branch.
		{
			name:       "valid npm CLI builder",
			artifact:   "provenance-npm-test-cli-v02-prega.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.3"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:       "valid npm CLI builder v1",
			artifact:   "provenance-npm-test-cli-v1-prega.tgz",
			source:     "github.com/sigstore/sigstore-js",
			pkgVersion: pointerTo("2.3.1"),
			pkgName:    pointerTo("sigstore"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:       "valid npm CLI builder short runner name",
			artifact:   "provenance-npm-test-cli-v02-prega.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.3"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test"),
			builderID:  pointerTo("https://github.com/actions/runner"),
		},
		{
			// The builderID for v1 should never be the "shortname".
			// https://github.com/npm/cli/blob/93883bb6459208a916584cad8c6c72a315cf32af/workspaces/libnpmpublish/lib/provenance.js#L58.
			name:       "valid npm CLI builder v1 short runner name",
			artifact:   "provenance-npm-test-cli-v1-prega.tgz",
			source:     "github.com/sigstore/sigstore-js",
			pkgVersion: pointerTo("2.3.1"),
			pkgName:    pointerTo("sigstore"),
			builderID:  pointerTo("https://github.com/actions/runner"),
			err:        serrors.ErrorInvalidBuilderID,
		},
		{
			name:       "valid npm CLI builder no builder",
			artifact:   "provenance-npm-test-cli-v02-prega.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.3"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test"),
			err:        serrors.ErrorInvalidBuilderID,
		},
		{
			name:       "valid npm CLI builder v1 no builder",
			artifact:   "provenance-npm-test-cli-v1-prega.tgz",
			source:     "github.com/sigstore/sigstore-js",
			pkgVersion: pointerTo("2.3.1"),
			pkgName:    pointerTo("sigstore"),
			err:        serrors.ErrorInvalidBuilderID,
		},
		{
			name:       "valid npm CLI builder mismatch builder",
			artifact:   "provenance-npm-test-cli-v02-prega.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.3"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test"),
			builderID:  pointerTo("https://github.com/actions/runner2"),
			err:        serrors.ErrorNotSupported,
		},
		{
			name:       "valid npm CLI builder v1 mismatch builder",
			artifact:   "provenance-npm-test-cli-v1-prega.tgz",
			source:     "github.com/sigstore/sigstore-js",
			pkgVersion: pointerTo("2.3.1"),
			pkgName:    pointerTo("sigstore"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted2"),
			err:        serrors.ErrorNotSupported,
		},
		{
			name:       "valid npm CLI builder no package name",
			artifact:   "provenance-npm-test-cli-v02-prega.tgz",
			pkgVersion: pointerTo("1.0.3"),
			source:     "github.com/laurentsimon/provenance-npm-test",
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:       "valid npm CLI builder v1 no package name",
			artifact:   "provenance-npm-test-cli-v1-prega.tgz",
			pkgVersion: pointerTo("2.3.1"),
			source:     "github.com/sigstore/sigstore-js",
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:      "valid npm CLI builder no package version",
			artifact:  "provenance-npm-test-cli-v02-prega.tgz",
			source:    "github.com/laurentsimon/provenance-npm-test",
			pkgName:   pointerTo("@laurentsimon/provenance-npm-test"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:      "valid npm CLI builder v1 no package version",
			artifact:  "provenance-npm-test-cli-v1-prega.tgz",
			source:    "github.com/sigstore/sigstore-js",
			pkgName:   pointerTo("sigstore"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
		},
		{
			name:      "valid npm CLI builder mismatch source",
			artifact:  "provenance-npm-test-cli-v02-prega.tgz",
			source:    "github.com/laurentsimon/provenance-npm-test2",
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
			err:       serrors.ErrorMismatchSource,
		},
		{
			name:      "valid npm CLI builder v1 mismatch source",
			artifact:  "provenance-npm-test-cli-v1-prega.tgz",
			source:    "github.com/sigstore/sigstore-js2",
			pkgName:   pointerTo("sigstore"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
			err:       serrors.ErrorMismatchSource,
		},
		{
			name:       "valid npm CLI builder mismatch package version",
			artifact:   "provenance-npm-test-cli-v02-prega.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.4"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
			err:        serrors.ErrorMismatchPackageVersion,
		},
		{
			name:       "valid npm CLI builder v1 mismatch package version",
			artifact:   "provenance-npm-test-cli-v1-prega.tgz",
			source:     "github.com/sigstore/sigstore-js",
			pkgVersion: pointerTo("2.3.2"),
			builderID:  pointerTo("https://github.com/actions/runner/github-hosted"),
			err:        serrors.ErrorMismatchPackageVersion,
		},
		{
			name:      "valid npm CLI builder mismatch package name",
			artifact:  "provenance-npm-test-cli-v02-prega.tgz",
			source:    "github.com/laurentsimon/provenance-npm-test",
			pkgName:   pointerTo("@laurentsimon/provenance-npm-test2"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
			err:       serrors.ErrorMismatchPackageName,
		},
		{
			name:      "valid npm CLI builder v1 mismatch package name",
			artifact:  "provenance-npm-test-cli-v1-prega.tgz",
			source:    "github.com/sigstore/sigstore-js",
			pkgName:   pointerTo("sigstore2"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
			err:       serrors.ErrorMismatchPackageName,
		},
		{
			name:      "invalid signature provenance npm CLI",
			artifact:  "provenance-npm-test-cli-v02-prega-invalidsigprov.tgz",
			source:    "github.com/laurentsimon/provenance-npm-test",
			pkgName:   pointerTo("@laurentsimon/provenance-npm-test"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
			err:       serrors.ErrorInvalidSignature,
		},
		{
			name:      "invalid signature provenance npm CLI v1",
			artifact:  "provenance-npm-test-cli-v1-prega-invalidsigprov.tgz",
			source:    "github.com/sigstore/sigstore-js",
			pkgName:   pointerTo("sigstore"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
			err:       serrors.ErrorInvalidSignature,
		},
		{
			name:      "invalid signature publish npm CLI",
			artifact:  "provenance-npm-test-cli-v02-prega-invalidsigpub.tgz",
			source:    "github.com/laurentsimon/provenance-npm-test",
			pkgName:   pointerTo("@laurentsimon/provenance-npm-test"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
			err:       serrors.ErrorInvalidSignature,
		},
		{
			name:      "invalid signature publish npm CLI v1",
			artifact:  "provenance-npm-test-cli-v1-prega-invalidsigpub.tgz",
			source:    "github.com/sigstore/sigstore-js",
			pkgName:   pointerTo("sigstore"),
			builderID: pointerTo("https://github.com/actions/runner/github-hosted"),
			err:       serrors.ErrorInvalidSignature,
		},
		// OSSF builder.
		{
			name:       "valid npm OSSF builder",
			artifact:   "provenance-npm-test-ossf.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test"),
			builderID:  pointerTo("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa3.yml"),
		},
		{
			name:       "valid npm OSSF builder no builder",
			artifact:   "provenance-npm-test-ossf.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test"),
			err:        serrors.ErrorInvalidBuilderID,
		},
		{
			name:       "valid npm OSSF builder mismatch builder",
			artifact:   "provenance-npm-test-ossf.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test"),
			builderID:  pointerTo("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa.yml"),
			err:        serrors.ErrorMismatchBuilderID,
		},
		{
			name:       "valid npm OSSF builder no package name",
			artifact:   "provenance-npm-test-ossf.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.5"),
			builderID:  pointerTo("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa3.yml"),
		},
		{
			name:      "valid npm OSSF builder no package version",
			artifact:  "provenance-npm-test-ossf.tgz",
			source:    "github.com/laurentsimon/provenance-npm-test",
			pkgName:   pointerTo("@laurentsimon/provenance-npm-test"),
			builderID: pointerTo("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa3.yml"),
		},
		{
			name:       "valid npm OSSF builder mismatch package name",
			artifact:   "provenance-npm-test-ossf.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test2"),
			builderID:  pointerTo("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa3.yml"),
			err:        serrors.ErrorMismatchPackageName,
		},
		{
			name:       "valid npm OSSF builder mismatch package version",
			artifact:   "provenance-npm-test-ossf.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.6"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test"),
			builderID:  pointerTo("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa3.yml"),
			err:        serrors.ErrorMismatchPackageVersion,
		},
		{
			name:       "valid npm OSSF builder mismatch mismatch source",
			artifact:   "provenance-npm-test-ossf.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test2",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test"),
			builderID:  pointerTo("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa3.yml"),
			err:        serrors.ErrorMismatchSource,
		},
		{
			name:       "invalid signature provenance npm OSSF builder",
			artifact:   "provenance-npm-test-ossf-invalidsigprov.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test"),
			builderID:  pointerTo("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa3.yml"),
			err:        serrors.ErrorInvalidSignature,
		},
		{
			name:       "invalid signature publish npm OSSF builder",
			artifact:   "provenance-npm-test-ossf-invalidsigpub.tgz",
			source:     "github.com/laurentsimon/provenance-npm-test",
			pkgVersion: pointerTo("1.0.5"),
			pkgName:    pointerTo("@laurentsimon/provenance-npm-test"),
			builderID:  pointerTo("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa3.yml"),
			err:        serrors.ErrorInvalidSignature,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			artifactPath := filepath.Clean(filepath.Join(TEST_DIR, "npm", "gha", tt.artifact))
			attestationsPath := fmt.Sprintf("%s.json", artifactPath)
			cmd := verify.VerifyNpmPackageCommand{
				AttestationsPath: attestationsPath,
				BuilderID:        tt.builderID,
				SourceURI:        tt.source,
				PackageName:      tt.pkgName,
				PackageVersion:   tt.pkgVersion,
			}

			_, err := cmd.Exec(context.Background(), []string{artifactPath})
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}

// Test_runVerifyVSA tests the CLI inputes of verify-vsa. More extensive tests are in
// slsa-verifier/verifiers/internal/vsa/verifier_test.go
func Test_runVerifyVSA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		attestationPath *string
		subjectDigests  *[]string
		verifierID      *string
		resourceURI     *string
		verifiedLevels  *[]string
		publicKeyPath   *string
		publicKeyID     *string
		err             error
	}{
		{
			name:            "success: gke",
			attestationPath: pointerTo("gce/v1/gke-gce-pre.bcid-vsa.jsonl"),
			subjectDigests:  pointerTo([]string{"gce_image_id:8970095005306000053"}),
			verifierID:      pointerTo("https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1"),
			resourceURI:     pointerTo("gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre"),
			verifiedLevels:  pointerTo([]string{"BCID_L1", "SLSA_BUILD_LEVEL_2"}),
			publicKeyPath:   pointerTo("gce/v1/vsa_signing_public_key.pem"),
			publicKeyID:     pointerTo("keystore://76574:prod:vsa_signing_public_key"),
		},
		{
			name:            "fail: gke, empty public key id",
			attestationPath: pointerTo("gce/v1/gke-gce-pre.bcid-vsa.jsonl"),
			publicKeyPath:   pointerTo("gce/v1/vsa_signing_public_key.pem"),
			publicKeyID:     pointerTo(""),
			err:             serrors.ErrorNoValidSignature,
		},
		{
			name:            "fail: gke, wrong key id",
			attestationPath: pointerTo("gce/v1/gke-gce-pre.bcid-vsa.jsonl"),
			publicKeyPath:   pointerTo("gce/v1/vsa_signing_public_key.pem"),
			publicKeyID:     pointerTo("my_key_id"),
			err:             serrors.ErrorNoValidSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			attestationPath := filepath.Clean(filepath.Join(TEST_DIR, "vsa", *tt.attestationPath))
			publicKeyPath := filepath.Clean(filepath.Join(TEST_DIR, "vsa", *tt.publicKeyPath))

			cmd := verify.VerifyVSACommand{
				AttestationPath: &attestationPath,
				SubjectDigests:  tt.subjectDigests,
				VerifierID:      tt.verifierID,
				ResourceURI:     tt.resourceURI,
				VerifiedLevels:  tt.verifiedLevels,
				PublicKeyPath:   &publicKeyPath,
				PublicKeyID:     tt.publicKeyID,
			}

			err := cmd.Exec(context.Background())
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}

func pointerTo[K any](object K) *K {
	return &object
}

func unwrapFull(t *testing.T, err error) error {
	for err != nil {
		t.Logf("%v", err)
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
	return nil
}
