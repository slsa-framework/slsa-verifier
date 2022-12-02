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
	"encoding/hex"
	"fmt"
	"io"
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
	artifactHash, err := getArtifactHash(artifacts[0])
	if err != nil {
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
		return nil, err
	}

	verifiedProvenance, outBuilderID, err := verifiers.VerifyArtifact(ctx, provenance, artifactHash, provenanceOpts, builderOpts)
	if err != nil {
		return nil, err
	}

	if c.PrintProvenance {
		fmt.Fprintf(os.Stdout, "%s\n", string(verifiedProvenance))
	}

	return outBuilderID, nil
}

func getArtifactHash(artifactPath string) (string, error) {
	f, err := os.Open(artifactPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
