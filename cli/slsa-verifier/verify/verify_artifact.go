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
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// Note: nil branch, tag, version-tag and builder-id means we ignore them during verification.
type VerifyArtifactCommand struct {
	ProvenancePath      string
	BuilderID           *string
	SourceURI           string
	SourceBranch        *string
	SourceTag           *string
	SourceVersionTag    *string
	BuildWorkflowInputs map[string]string
	PrintProvenance     bool
}

func (c *VerifyArtifactCommand) Exec(ctx context.Context, artifacts []string) (*utils.TrustedBuilderID, error) {
	var builderID *utils.TrustedBuilderID

	for _, artifact := range artifacts {
		artifactHash, err := computeFileHash(artifact, sha256.New())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verifying artifact %s: FAILED: %v\n\n", artifact, err)
			return nil, err
		}

		provenanceOpts := &options.ProvenanceOpts{
			ExpectedSourceURI:      c.SourceURI,
			ExpectedBranch:         c.SourceBranch,
			ExpectedDigest:         artifactHash,
			ExpectedVersionedTag:   c.SourceVersionTag,
			ExpectedTag:            c.SourceTag,
			ExpectedWorkflowInputs: c.BuildWorkflowInputs,
		}

		builderOpts := &options.BuilderOpts{
			ExpectedID: c.BuilderID,
		}

		provenance, err := os.ReadFile(c.ProvenancePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verifying artifact %s: FAILED: %v\n\n", artifact, err)
			return nil, err
		}

		verifiedProvenance, outBuilderID, err := verifiers.VerifyArtifact(ctx, provenance, artifactHash, provenanceOpts, builderOpts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verifying artifact %s: FAILED: %v\n\n", artifact, err)
			return nil, err
		}

		if c.PrintProvenance {
			fmt.Fprintf(os.Stdout, "%s\n", string(verifiedProvenance))
		}

		if builderID == nil {
			builderID = outBuilderID
		} else if *builderID != *outBuilderID {
			err := fmt.Errorf("encountered different builderIDs %v %v", builderID, outBuilderID)
			fmt.Fprintf(os.Stderr, "Verifying artifact %s: FAILED: %v\n\n", artifact, err)
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "Verifying artifact %s: PASSED\n\n", artifact)
	}

	return builderID, nil
}
