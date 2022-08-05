package gha

import (
	"context"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/slsa-framework/slsa-verifier/options"
	register "github.com/slsa-framework/slsa-verifier/register"
)

const VerifierName = "GCB"

//nolint:gochecknoinits
func init() {
	register.RegisterVerifier(VerifierName, GCBVerifierNew())
}

type GCBVerifier struct{}

func GCBVerifierNew() *GCBVerifier {
	return &GCBVerifier{}
}

// Match a BuilderID.
func (v *GCBVerifier) Match(builderID string) bool {
	// This verifier only supports the GCB builders.
	return strings.HasPrefix(builderID, "https://cloudbuild.googleapis.com/GoogleHostedWorker@")
}

// VerifyArtifact verifies provenance for an artifact.
func (v *GCBVerifier) VerifyArtifact(ctx context.Context,
	provenance []byte, artifactHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, string, error) {
	return nil, "todo", serrors.ErrorNotSupported
}

// VerifyImage verifies provenance for an OCI image.
func (v *GCBVerifier) VerifyImage(ctx context.Context,
	provenance []byte, artifactHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, string, error) {
	return nil, "todo", serrors.ErrorNotSupported
}
