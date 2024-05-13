package register

import (
	"context"

	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

var SLSAVerifiers = make(map[string]SLSAVerifier)

type SLSAVerifier interface {
	// IsAuthoritativeFor checks whether a verifier can
	// verify provenance for a given builder identified by its
	// `BuilderID`.
	IsAuthoritativeFor(builderIDName string) bool

	// VerifyArtifact verifies a provenance for a supplied artifact.
	VerifyArtifact(ctx context.Context,
		provenance []byte, artifactHash string,
		provenanceOpts *options.ProvenanceOpts,
		builderOpts *options.BuilderOpts,
	) ([]byte, *utils.TrustedBuilderID, error)

	// VerifyImage verifies a provenance for a supplied OCI image.
	VerifyImage(ctx context.Context,
		provenance []byte, artifactImage string,
		provenanceOpts *options.ProvenanceOpts,
		builderOpts *options.BuilderOpts,
	) ([]byte, *utils.TrustedBuilderID, error)

	VerifyNpmPackage(ctx context.Context,
		attestations []byte, tarballHash string,
		provenanceOpts *options.ProvenanceOpts,
		builderOpts *options.BuilderOpts,
	) ([]byte, *utils.TrustedBuilderID, error)

	VerifyNpmPackageWithSigstoreTufClient(ctx context.Context,
		attestations []byte, tarballHash string,
		provenanceOpts *options.ProvenanceOpts,
		builderOpts *options.BuilderOpts, sigstoreTufClient utils.SigstoreTufClient,
	) ([]byte, *utils.TrustedBuilderID, error)
}

func RegisterVerifier(name string, verifier SLSAVerifier) {
	SLSAVerifiers[name] = verifier
}
