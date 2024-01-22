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
	"fmt"
	"os"

	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils/container"
)

type ComputeDigestFn func(string) (string, error)

// Note: nil branch, tag, version-tag and builder-id means we ignore them during verification.
type VerifyImageCommand struct {
	// May be nil if supplied alongside in the registry
	ProvenancePath       *string
	ProvenanceRepository *string
	BuilderID            *string
	SourceURI            string
	SourceBranch         *string
	SourceTag            *string
	SourceVersionTag     *string
	BuildWorkflowInputs  map[string]string
	PrintProvenance      bool
}

func (c *VerifyImageCommand) Exec(ctx context.Context, artifacts []string) (*utils.TrustedBuilderID, error) {
	artifactImage := artifacts[0]

	// Verify that the reference is immutable.
	digest, err := container.GetDigestFromImmutableReference(artifactImage)
	if err != nil {
		return nil, err
	}

	provenanceOpts := &options.ProvenanceOpts{
		ExpectedSourceURI:            c.SourceURI,
		ExpectedBranch:               c.SourceBranch,
		ExpectedDigest:               digest,
		ExpectedVersionedTag:         c.SourceVersionTag,
		ExpectedTag:                  c.SourceTag,
		ExpectedProvenanceRepository: c.ProvenanceRepository,
		ExpectedWorkflowInputs:       c.BuildWorkflowInputs,
	}

	builderOpts := &options.BuilderOpts{
		ExpectedID: c.BuilderID,
	}

	var provenance []byte
	if c.ProvenancePath != nil {
		provenance, err = os.ReadFile(*c.ProvenancePath)
		if err != nil {
			return nil, err
		}
	}

	verifiedProvenance, outBuilderID, err := verifiers.VerifyImage(ctx, artifacts[0], provenance, provenanceOpts, builderOpts)

	if err != nil {
		return nil, err
	}

	if c.PrintProvenance {
		fmt.Fprintf(os.Stdout, "%s\n", string(verifiedProvenance))
	}

	return outBuilderID, nil
}
