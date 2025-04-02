// Copyright 2025 SLSA Authors
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
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

type VerifyGithubAttestationCommand struct {
	AttestationPath     string
	BuilderID           *string
	SourceURI           string
	BuildWorkflowInputs map[string]string
	PrintAttestation    bool
}

func (c *VerifyGithubAttestationCommand) Exec(ctx context.Context, artifact string) (*utils.TrustedBuilderID, error) {
	if !options.ExperimentalEnabled() {
		err := errors.New("feature support is only provided in SLSA_VERIFIER_EXPERIMENTAL mode")
		fmt.Fprintf(os.Stderr, "Verifying github attestation: FAILED: %v\n\n", err)
		return nil, err
	}

	artifactHash, err := computeFileHash(artifact, sha256.New())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verifying artifact %s: FAILED: %v\n\n", artifact, err)
		return nil, err
	}

	provenanceOpts := &options.ProvenanceOpts{
		ExpectedSourceURI:      c.SourceURI,
		ExpectedDigest:         artifactHash,
		ExpectedWorkflowInputs: c.BuildWorkflowInputs,
	}

	builderOpts := &options.BuilderOpts{
		ExpectedID: c.BuilderID,
	}

	attestation, err := os.ReadFile(c.AttestationPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verifying artifact %s: FAILED: %v\n\n", artifact, err)
		return nil, err
	}

	verifiedAttestation, outBuilderID, err := verifiers.VerifyGithubAttestation(ctx, attestation, provenanceOpts, builderOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verifying artifact %s: FAILED: %v\n\n", artifact, err)
		return nil, err
	}

	if c.PrintAttestation {
		fmt.Fprintf(os.Stdout, "%s\n", string(verifiedAttestation))
	}

	fmt.Fprintf(os.Stderr, "Verifying artifact %s: PASSED\n\n", artifact)
	return outBuilderID, nil
}
