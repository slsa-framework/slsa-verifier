package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/layout"
	"github.com/slsa-framework/slsa-verifier/pkg"

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
var golangGeneratorVersions = []string{"v0.0.2", "v1.1.1"}

func Test_runVerifyGo(t *testing.T) {
	// t.Parallel()
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
			err:      pkg.ErrorMismatchBranch,
		},
		{
			name:     "wrong source append A",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/laurentsimon/slsa-verifier-test-genA",
			err:      pkg.ErrorMismatchRepository,
		},
		{
			name:     "wrong source prepend A",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/laurentsimon/slsa-verifier-test-gen",
			err:      pkg.ErrorMismatchRepository,
		},
		{
			name:     "wrong source middle A",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/Alaurentsimon/slsa-verifier-test-gen",
			err:      pkg.ErrorMismatchRepository,
		},
		{
			name:     "tag no match empty tag workflow_dispatch",
			artifact: "binary-linux-amd64-workflow_dispatch",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v1.2.3"),
			err:      pkg.ErrorMismatchTag,
		},
		{
			name:        "versioned tag no match empty tag workflow_dispatch",
			artifact:    "binary-linux-amd64-workflow_dispatch",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v1"),
			err:         pkg.ErrorInvalidSemver,
		},
		// Provenance contains tag = v13.0.30.
		{
			name:     "tag v31.0.29 no match v13.0.30",
			artifact: "binary-linux-amd64-push-v13.0.30",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v13.0.29"),
			err:      pkg.ErrorMismatchTag,
		},
		{
			name:     "tag v13.0 no match v13.0.30",
			artifact: "binary-linux-amd64-push-v13.0.30",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v13.0"),
			err:      pkg.ErrorMismatchTag,
		},
		{
			name:     "tag v13 no match v13.0.30",
			artifact: "binary-linux-amd64-push-v13.0.30",
			source:   "github.com/slsa-framework/example-package",
			ptag:     pString("v13"),
			err:      pkg.ErrorMismatchTag,
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
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v0 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v0"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.1 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.1"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v12.9 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v12.9"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.0.29 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0.29"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.0.31 no match push-v13.0.30",
			artifact:    "binary-linux-amd64-push-v13.0.30",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.0.31"),
			err:         pkg.ErrorMismatchVersionedTag,
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
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13.2 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13.2"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v0 no match push-v14",
			artifact:    "binary-linux-amd64-push-v14",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v0"),
			err:         pkg.ErrorMismatchVersionedTag,
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
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.2.3 match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.2.3"),
			err:         pkg.ErrorMismatchVersionedTag,
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
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.1.1 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.1.1"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v14.3.1 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v14.3.1"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v13 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v13"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15"),
			err:         pkg.ErrorMismatchVersionedTag,
		},
		{
			name:        "versioned v15.1 no match push-v14.2",
			artifact:    "binary-linux-amd64-push-v14.2",
			source:      "github.com/slsa-framework/example-package",
			pversiontag: pString("v15.1"),
			err:         pkg.ErrorMismatchVersionedTag,
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
			err:       pkg.ErrorNoValidRekorEntries,
			noversion: true,
		},
		{
			name:      "malicious: untrusted builder",
			artifact:  "binary-linux-amd64-untrusted-builder",
			source:    "github.com/slsa-framework/example-package",
			err:       pkg.ErrorUntrustedReusableWorkflow,
			noversion: true,
		},
		{
			name:      "malicious: invalid signature expired certificate",
			artifact:  "binary-linux-amd64-expired-cert",
			source:    "github.com/slsa-framework/example-package",
			err:       pkg.ErrorNoValidRekorEntries,
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

			checkVersions := golangGeneratorVersions
			if tt.noversion {
				checkVersions = []string{""}
			}

			for _, v := range checkVersions {
				branch := tt.branch
				if branch == "" {
					branch = "main"
				}

				artifactPath = filepath.Clean(fmt.Sprintf("./testdata/go/%v/%s", v, tt.artifact))
				provenancePath = fmt.Sprintf("%s.intoto.jsonl", artifactPath)

				_, err := runVerify("", artifactPath,
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

func TestContainerVerification(t *testing.T) {
	runContainerVerification = func(ctx context.Context, path string) ([]oci.Signature, string, error) {
		roots, err := fulcio.GetRoots()
		if err != nil {
			return nil, "", err
		}

		atts, _, err := cosign.VerifyLocalImageAttestations(ctx, path, &cosign.CheckOpts{
			RootCerts: roots,
		})
		if err != nil {
			return nil, "", err
		}
		se, err := layout.SignedImageIndex(path)
		if err != nil {
			return nil, "", err
		}

		var h v1.Hash
		// Verify either an image index or image.
		ii, err := se.SignedImageIndex(v1.Hash{})
		if err != nil {
			return nil, "", err
		}
		i, err := se.SignedImage(v1.Hash{})
		if err != nil {
			return nil, "", err
		}
		switch {
		case ii != nil:
			h, err = ii.Digest()
			if err != nil {
				return nil, "", err
			}
		case i != nil:
			h, err = i.Digest()
			if err != nil {
				return nil, "", err
			}
		default:
			return nil, "", err
		}
		return atts, h.Hex, err
	}

	_, err := runVerify("./testdata/container/v1.2.0/container_schedule_main", artifactPath,
		provenancePath,
		"github.com/slsa-framework/example-package", "main",
		nil, nil)
	if err != nil {
		t.Errorf(err.Error())
	}
}
