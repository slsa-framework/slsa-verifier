package main

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	pkg "github.com/slsa-framework/slsa-verifier/pkg"
)

func errCmp(e1, e2 error) bool {
	return errors.Is(e1, e2) || errors.Is(e2, e1)
}

func pString(s string) *string {
	return &s
}

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
	}{
		{
			name:     "valid main branch default",
			artifact: "./testdata/binary-linux-amd64-workflow_dispatch",
			source:   "github.com/asraa/slsa-on-github-test",
		},
		{
			name:     "valid main branch set",
			artifact: "./testdata/binary-linux-amd64-workflow_dispatch",
			source:   "github.com/asraa/slsa-on-github-test",
			branch:   "main",
		},
		{
			name:     "wrong branch master",
			artifact: "./testdata/binary-linux-amd64-workflow_dispatch",
			source:   "github.com/asraa/slsa-on-github-test",
			branch:   "master",
			err:      pkg.ErrorMismatchBranch,
		},
		{
			name:     "wrong source append A",
			artifact: "./testdata/binary-linux-amd64-workflow_dispatch",
			source:   "github.com/asraa/slsa-on-github-testA",
			err:      pkg.ErrorMismatchRepository,
		},
		{
			name:     "wrong source prepend A",
			artifact: "./testdata/binary-linux-amd64-workflow_dispatch",
			source:   "Agithub.com/asraa/slsa-on-github-test",
			err:      pkg.ErrorMismatchRepository,
		},
		{
			name:     "wrong source middle A",
			artifact: "./testdata/binary-linux-amd64-workflow_dispatch",
			source:   "github.com/Aasraa/slsa-on-github-test",
			err:      pkg.ErrorMismatchRepository,
		},
		{
			name:     "tag no match empty tag workflow_dispatch",
			artifact: "./testdata/binary-linux-amd64-workflow_dispatch",
			source:   "github.com/asraa/slsa-on-github-test",
			ptag:     pString("v1.2.3"),
			err:      pkg.ErrorMismatchTag,
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch",
			artifact:    "./testdata/binary-linux-amd64-workflow_dispatch",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1"),
			err:         pkg.ErrorInvalidSemver,
		},
		{
			name:     "tag v1.2.3 no match v1.2.4",
			artifact: "./testdata/binary-linux-amd64-push-v1.2.4",
			source:   "github.com/asraa/slsa-on-github-test",
			ptag:     pString("v1.2.3"),
			err:      pkg.ErrorMismatchTag,
		},
		{
			name:     "tag v1.2 no match v1.2.4",
			artifact: "./testdata/binary-linux-amd64-push-v1.2.4",
			source:   "github.com/asraa/slsa-on-github-test",
			ptag:     pString("v1.2"),
			err:      pkg.ErrorMismatchTag,
		},
		{
			name:     "tag v1 no match v1.2.4",
			artifact: "./testdata/binary-linux-amd64-push-v1.2.4",
			source:   "github.com/asraa/slsa-on-github-test",
			ptag:     pString("v1"),
			err:      pkg.ErrorMismatchTag,
		},
		// Provenance contains tag = v1.2.4.
		{
			name:        "versioned v1.2.4 match push-v1.2.4",
			artifact:    "./testdata/binary-linux-amd64-push-v1.2.4",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1.2.4"),
		},
		{
			name:        "versioned v1.2 match push-v1.2.4",
			artifact:    "./testdata/binary-linux-amd64-push-v1.2.4",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1.2"),
		},
		{
			name:        "versioned v1 match push-v1.2.4",
			artifact:    "./testdata/binary-linux-amd64-push-v1.2.4",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1"),
		},
		{
			name:        "versioned v2 no match push-v1.2.4",
			artifact:    "./testdata/binary-linux-amd64-push-v1.2.4",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v2"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v0 no match push-v1.2.4",
			artifact:    "./testdata/binary-linux-amd64-push-v1.2.4",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v0"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v1.3 no match push-v1.2.4",
			artifact:    "./testdata/binary-linux-amd64-push-v1.2.4",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1.3"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v1.1 no match push-v1.2.4",
			artifact:    "./testdata/binary-linux-amd64-push-v1.2.4",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1.1"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v1.2.3 no match push-v1.2.4",
			artifact:    "./testdata/binary-linux-amd64-push-v1.2.4",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1.2.3"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v1.2.5 no match push-v1.2.4",
			artifact:    "./testdata/binary-linux-amd64-push-v1.2.4",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1.2.5"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		// Provenance contains tag = v2.
		{
			name:        "versioned v2 match push-v2",
			artifact:    "./testdata/binary-linux-amd64-push-v2",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v2"),
		},
		{
			name:        "versioned v2.0 match push-v2",
			artifact:    "./testdata/binary-linux-amd64-push-v2",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v2.0"),
		},
		{
			name:        "versioned v2.1 no match push-v2",
			artifact:    "./testdata/binary-linux-amd64-push-v2",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v2.1"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v1 no match push-v2",
			artifact:    "./testdata/binary-linux-amd64-push-v2",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v3 no match push-v2",
			artifact:    "./testdata/binary-linux-amd64-push-v2",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v3"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v1.2 no match push-v2",
			artifact:    "./testdata/binary-linux-amd64-push-v2",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1.2"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v3 no match push-v2",
			artifact:    "./testdata/binary-linux-amd64-push-v2",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v3"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v0 no match push-v2",
			artifact:    "./testdata/binary-linux-amd64-push-v2",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v0"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		// Provenance contains tag = v2.5.
		{
			name:        "versioned v2.5 match push-v2.5",
			artifact:    "./testdata/binary-linux-amd64-push-v2.5",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v2.5"),
		},
		{
			name:        "versioned v2.5.1 match push-v2.5",
			artifact:    "./testdata/binary-linux-amd64-push-v2.5",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v2.5.1"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v2.5.3 match push-v2.5",
			artifact:    "./testdata/binary-linux-amd64-push-v2.5",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v2.5.3"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v2 match push-v2.5",
			artifact:    "./testdata/binary-linux-amd64-push-v2.5",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v2"),
		},
		{
			name:        "versioned v2.4 no match push-v2.5",
			artifact:    "./testdata/binary-linux-amd64-push-v2.5",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v2.4"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v2.4.1 no match push-v2.5",
			artifact:    "./testdata/binary-linux-amd64-push-v2.5",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v2.4.1"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v2.4.5 no match push-v2.5",
			artifact:    "./testdata/binary-linux-amd64-push-v2.5",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v2.4.5"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v1 no match push-v2.5",
			artifact:    "./testdata/binary-linux-amd64-push-v2.5",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v1"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v3 no match push-v2.5",
			artifact:    "./testdata/binary-linux-amd64-push-v2.5",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v3"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v3.1 no match push-v2.5",
			artifact:    "./testdata/binary-linux-amd64-push-v2.5",
			source:      "github.com/asraa/slsa-on-github-test",
			pversiontag: pString("v3.1"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		// TODO(laurent): add tests for sepcial cases of buidlers' ref.
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			branch := tt.branch
			if branch == "" {
				branch = "main"
			}

			err := runVerify(tt.artifact,
				tt.artifact+".intoto.jsonl",
				tt.source, branch,
				tt.ptag, tt.pversiontag)

			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
			}
		})
	}
}
