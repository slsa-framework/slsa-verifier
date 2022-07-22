package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"golang.org/x/mod/semver"

	"github.com/slsa-framework/slsa-verifier/verification"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func errCmp(e1, e2 error) bool {
	return errors.Is(e1, e2) || errors.Is(e2, e1)
}

func pString(s string) *string {
	return &s
}

// Versions of the builders to test.
// TODO: Enable v1.0.0 for go builder
var generatorVersions = map[string][]string{
	"v0.0.2": {"go"},
	"v1.1.1": {"go"},
	"v1.2.0": {"generic"},
}

const TEST_DIR = "./testdata"

func Test_runVerify(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		artifact    string
		source      string
		branch      string
		ptag        *string
		pversiontag *string
		err         error
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
			name:     "valid main branch set",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
			branch:   "main",
		},
		{
			name:     "wrong branch master",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
			branch:   "master",
			err:      verification.ErrorMismatchBranch,
		},
		{
			name:     "wrong source append A",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/laurentsimon/slsa-verifier-test-genA",
			err:      verification.ErrorMismatchRepository,
		},
		{
			name:     "wrong source prepend A",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/laurentsimon/slsa-verifier-test-gen",
			err:      verification.ErrorMismatchRepository,
		},
		{
			name:     "wrong source middle A",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/Alaurentsimon/slsa-verifier-test-gen",
			err:      verification.ErrorMismatchRepository,
		},
		{
			name:     "tag no match empty tag workflow_dispatch",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v1.2.3"),
			err:      verification.ErrorMismatchTag,
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch",
			artifact:    "binary-linux-amd64-workflow_dispatch",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v1"),
			err:         verification.ErrorInvalidSemver,
		},
		// Provenance contains tag = v13.0.30.
		{
			name:     "tag v31.0.29 no match v13.0.30",
			artifact: "binary-linux-amd64-push-v13.0.30",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v13.0.29"),
			err:      verification.ErrorMismatchTag,
		},
		{
			name:     "tag v13.0 no match v13.0.30",
			artifact: "binary-linux-amd64-push-v13.0.30",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v13.0"),
			err:      verification.ErrorMismatchTag,
		},
		{
			name:     "tag v13 no match v13.0.30",
			artifact: "binary-linux-amd64-push-v13.0.30",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v13"),
			err:      verification.ErrorMismatchTag,
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
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v0 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v0"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.1 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.1"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v12.9 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v12.9"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.0.29 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0.29"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.0.31 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0.31"),
			err:         verification.ErrorMismatchVersionedTag,
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
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.2 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.2"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v0 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v0"),
			err:         verification.ErrorMismatchVersionedTag,
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
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.2.3 match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.2.3"),
			err:         verification.ErrorMismatchVersionedTag,
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
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.1.1 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.1.1"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.3.1 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.3.1"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         verification.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15.1 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15.1"),
			err:         verification.ErrorMismatchVersionedTag,
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
		// Special case of the e2e test repository building builder from head.
		{
			name:      "e2e test repository verified with builder at head",
			artifact:  "binary-linux-amd64-e2e-builder-repo",
			source:    "github.com/slsa-framework/example-package",
			branch:    "main",
			noversion: true,
		},
		// Malicious builders and workflows.
		{
			name:      "rekor upload bypassed",
			artifact:  "binary-linux-amd64-no-tlog-upload",
			source:    "github.com/slsa-framework/example-package",
			err:       verification.ErrorNoValidRekorEntries,
			noversion: true,
		},
		{
			name:      "malicious: untrusted builder",
			artifact:  "binary-linux-amd64-untrusted-builder",
			source:    "github.com/slsa-framework/example-package",
			err:       verification.ErrorUntrustedReusableWorkflow,
			noversion: true,
		},
		{
			name:      "malicious: invalid signature expired certificate",
			artifact:  "binary-linux-amd64-expired-cert",
			source:    "github.com/slsa-framework/example-package",
			err:       verification.ErrorNoValidRekorEntries,
			noversion: true,
		},
		// Regression test of sharded UUID
		{
			name:      "regression: sharded uuids",
			artifact:  "binary-linux-amd64-sharded",
			source:    "github.com/slsa-framework/slsa-verifier",
			branch:    "release/v1.0",
			noversion: true,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel()
			getBuildersAndVersions := func(minversion string, ttBuilders []string) []string {
				res := []string{}
				builders := tt.builders
				if len(builders) == 0 {
					testdataDir, err := ioutil.ReadDir(TEST_DIR)
					if err != nil {
						t.Error(err)
					}
					for _, f := range testdataDir {
						if f.IsDir() {
							// These are the builder subfolders
							builders = append(builders, f.Name())
						}
					}
				}
				for _, builder := range builders {
					builderDir, err := ioutil.ReadDir(filepath.Join(TEST_DIR, builder))
					if err != nil {
						t.Error(err)
					}
					for _, f := range builderDir {
						// Builder subfolders are semantic version strings.
						// Compare if a min version is given.
						if f.IsDir() && semver.Compare(minversion, f.Name()) <= 0 {
							// These are the supported versions of the builder
							res = append(res, filepath.Join(builder, f.Name()))
						}
					}
				}
				return res
			}

			checkVersions := getBuildersAndVersions(tt.minversion, tt.builders)
			if tt.noversion {
				checkVersions = []string{""}
			}

			for _, v := range checkVersions {
				branch := tt.branch
				if branch == "" {
					branch = "main"
				}

				artifactPath := filepath.Clean(filepath.Join(TEST_DIR, v, tt.artifact))
				provenancePath := fmt.Sprintf("%s.intoto.jsonl", artifactPath)

				_, err := runVerify(artifactPath,
					provenancePath,
					tt.source, branch,
					tt.ptag, tt.pversiontag)

				if !errCmp(err, tt.err) {
					t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
				}
			}
		})
	}
}
