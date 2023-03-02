// Copyright 2022 SLSA Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"

	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

type VerifyNpmPackageCommand struct {
	AttestationsPath    string
	BuilderID           *string
	SourceURI           string
	SourceBranch        *string
	SourceTag           *string
	SourceVersionTag    *string
	PackageName         *string
	PackageVersion      *string
	BuildWorkflowInputs map[string]string
	PrintProvenance     bool
}

func (c *VerifyNpmPackageCommand) Exec(ctx context.Context, tarballs []string) (*utils.TrustedBuilderID, error) {
	var builderID *utils.TrustedBuilderID
	if !options.ExperimentalEnabled() {
		err := errors.New("feature support is only provided in SLSA_VERIFIER_EXPERIMENTAL mode")
		fmt.Fprintf(os.Stderr, "Verifying npm package: FAILED: %v\n\n", err)
		return nil, err
	}
	for _, tarball := range tarballs {
		tarballHash, err := computeFileHash(tarball, sha512.New())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verifying npm package %s: FAILED: %v\n\n", tarball, err)
			return nil, err
		}

		if c.AttestationsPath == "" {
			fmt.Fprintf(os.Stderr, "Verifying npm package %s: FAILED: %v\n\n", tarball, err)
			return nil, err
		}
		provenanceOpts := &options.ProvenanceOpts{
			ExpectedSourceURI:      c.SourceURI,
			ExpectedBranch:         c.SourceBranch,
			ExpectedDigest:         tarballHash,
			ExpectedVersionedTag:   c.SourceVersionTag,
			ExpectedTag:            c.SourceTag,
			ExpectedWorkflowInputs: c.BuildWorkflowInputs,
			ExpectedPackageName:    c.PackageName,
			ExpectedPackageVersion: c.PackageVersion,
		}

		builderOpts := &options.BuilderOpts{
			ExpectedID: c.BuilderID,
		}

		attestations, err := os.ReadFile(c.AttestationsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verifying npm package %s: FAILED: %v\n\n", tarball, err)
			return nil, err
		}

		verifiedProvenance, outBuilderID, err := verifiers.VerifyNpmPackage(ctx, attestations, tarballHash, provenanceOpts, builderOpts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verifying npm package %s: FAILED: %v\n\n", tarball, err)
			return nil, err
		}

		if c.PrintProvenance {
			fmt.Fprintf(os.Stdout, "%s\n", string(verifiedProvenance))
		}

		builderID = outBuilderID
		fmt.Fprintf(os.Stderr, "Verifying npm package %s: PASSED\n\n", tarball)
	}

	return builderID, nil
}
