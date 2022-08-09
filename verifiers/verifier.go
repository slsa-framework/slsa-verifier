package verifiers

import (
	"context"
	"fmt"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/slsa-framework/slsa-verifier/options"
	"github.com/slsa-framework/slsa-verifier/register"
	_ "github.com/slsa-framework/slsa-verifier/verifiers/internal/gcb"
	"github.com/slsa-framework/slsa-verifier/verifiers/internal/gha"
)

func Verify(ctx context.Context, artifactReference string,
	provenance []byte, artifactHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, string, error) {
	// By default, use the GHA builders
	verifier := register.SLSAVerifiers[gha.VerifierName]

	// If user provids a builderID, find the right verifier based on its ID.
	if builderOpts.ExpectedID != nil &&
		*builderOpts.ExpectedID != "" {
		foundBuilder := false
		for _, v := range register.SLSAVerifiers {
			if v.IsAuthoritativeFor(*builderOpts.ExpectedID) {
				foundBuilder = true
				verifier = v
				break
			}
		}
		if !foundBuilder {
			// No builder found.
			return nil, "", fmt.Errorf("%w: %s", serrors.ErrorVerifierNotSupported, *builderOpts.ExpectedID)
		}
	}

	// By default, try the GHA builders.
	if artifactReference != "" {
		return verifier.VerifyImage(ctx, artifactReference, provenanceOpts, builderOpts)
	}
	return verifier.VerifyArtifact(ctx, provenance, artifactHash,
		provenanceOpts, builderOpts)
}
