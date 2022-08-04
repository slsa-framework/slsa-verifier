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
) ([]byte, error) {
	// If a builder is passed as entry, find the right verifier.
	if builderOpts.ExpectedID != nil &&
		*builderOpts.ExpectedID != "" {
		for _, v := range register.SLSAVerifiers {
			if v.Match(*builderOpts.ExpectedID) {
				return v.Verify(ctx, provenance, artifactHash,
					provenanceOpts, builderOpts)
			}
		}
		// No builder found.
		return nil, fmt.Errorf("%w: %s", serrors.ErrorVerifierNotSupported, *builderOpts.ExpectedID)
	}

	// By default, try the GHA builders.
	return register.SLSAVerifiers[gha.VerifierName].Verify(ctx, provenance, artifactHash,
		provenanceOpts, builderOpts)
}
