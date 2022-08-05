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

func Verify(ctx context.Context,
	provenance []byte, artifactHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, string, error) {
	// If user provids a builderID, find the right verifier
	// based on its ID.
	if builderOpts.ExpectedID != nil &&
		*builderOpts.ExpectedID != "" {
		for _, v := range register.SLSAVerifiers {
			if v.IsAuthoritativeFor(*builderOpts.ExpectedID) {
				return v.VerifyArtifact(ctx, provenance, artifactHash,
					provenanceOpts, builderOpts)
			}
		}
		// No builder found.
		return nil, "", fmt.Errorf("%w: %s", serrors.ErrorVerifierNotSupported, *builderOpts.ExpectedID)
	}

	// By default, try the GHA builders.
	return register.SLSAVerifiers[gha.VerifierName].VerifyArtifact(ctx, provenance, artifactHash,
		provenanceOpts, builderOpts)
}
