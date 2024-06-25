package verifiers

import (
	"context"
	"fmt"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/register"
	_ "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/vsa"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

func getVerifier(builderOpts *options.BuilderOpts) (register.SLSAVerifier, error) {
	// By default, use the GHA builders
	verifier := register.SLSAVerifiers[gha.VerifierName]

	// If user provids a builderID, find the right verifier based on its ID.
	if builderOpts.ExpectedID != nil &&
		*builderOpts.ExpectedID != "" {
		name, _, err := utils.ParseBuilderID(*builderOpts.ExpectedID, false)
		if err != nil {
			return nil, err
		}
		for _, v := range register.SLSAVerifiers {
			if v.IsAuthoritativeFor(name) {
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
) ([]byte, *utils.TrustedBuilderID, error) {
	verifier, err := getVerifier(builderOpts)
	if err != nil {
		return nil, nil, err
	}
	return verifier.VerifyImage(ctx, provenance, artifactImage, provenanceOpts, builderOpts)
}

func VerifyArtifact(ctx context.Context,
	provenance []byte, artifactHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, *utils.TrustedBuilderID, error) {
	verifier, err := getVerifier(builderOpts)
	if err != nil {
		return nil, nil, err
	}

	return verifier.VerifyArtifact(ctx, provenance, artifactHash,
		provenanceOpts, builderOpts)
}

func VerifyNpmPackage(ctx context.Context,
	attestations []byte, tarballHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, *utils.TrustedBuilderID, error) {
	verifier, err := getVerifier(builderOpts)
	if err != nil {
		return nil, nil, err
	}

	return verifier.VerifyNpmPackage(ctx, attestations, tarballHash,
		provenanceOpts, builderOpts)
}

// VerifyVSA verifies the VSA attestation. It returns the attestation base64-decoded from the envelope.
// We don't return a TrustedBuilderID. Instead, the user can user can parse the builderID separately, perhaps with
// https://pkg.go.dev/golang.org/x/mod/semver
func VerifyVSA(ctx context.Context,
	attestation []byte,
	vsaOpts *options.VSAOpts,
	verificationOpts *options.VerificationOpts,
) ([]byte, error) {
	return vsa.VerifyVSA(ctx, attestation, vsaOpts, verificationOpts)
}
