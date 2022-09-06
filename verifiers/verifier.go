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

func getVerifier(builderOpts *options.BuilderOpts) (register.SLSAVerifier, error) {
	// By default, use the GHA builders
	verifier := register.SLSAVerifiers[gha.VerifierName]

	// If user provids a builderID, find the right verifier based on its ID.
	if builderOpts.ExpectedID != nil &&
		*builderOpts.ExpectedID != "" {
		for _, v := range register.SLSAVerifiers {
			if v.IsAuthoritativeFor(*builderOpts.ExpectedID) {
				return v, nil
			}
		}
		// No builder found.
		return nil, fmt.Errorf("%w: %s", serrors.ErrorVerifierNotSupported, *builderOpts.ExpectedID)
	}

	return verifier, nil
}

func VerifyImage(ctx context.Context, artifactImage string,
	provenance []byte,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, string, error) {
	verifier, err := getVerifier(builderOpts)
	if err != nil {
		return nil, "", err
	}

	return verifier.VerifyImage(ctx, provenance, artifactImage, provenanceOpts, builderOpts)
}

func VerifyArtifact(ctx context.Context,
	provenance []byte, artifactHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, string, error) {
	verifier, err := getVerifier(builderOpts)
	if err != nil {
		return nil, "", err
	}

	return verifier.VerifyArtifact(ctx, provenance, artifactHash,
		provenanceOpts, builderOpts)
}
