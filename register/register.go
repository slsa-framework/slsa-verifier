package register

import (
	"context"

	"github.com/slsa-framework/slsa-verifier/options"
	"github.com/slsa-framework/slsa-verifier/verifiers/utils"
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
	) ([]byte, *utils.BuilderID, error)

	// VerifyImage verifies a provenance for a supplied OCI image.
	VerifyImage(ctx context.Context,
		provenance []byte, artifactImage string,
		provenanceOpts *options.ProvenanceOpts,
		builderOpts *options.BuilderOpts,
	) ([]byte, *utils.BuilderID, error)
}

func RegisterVerifier(name string, verifier SLSAVerifier) {
	SLSAVerifiers[name] = verifier
}
