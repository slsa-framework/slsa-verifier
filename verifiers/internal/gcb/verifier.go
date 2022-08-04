package gha

import (
	"context"
	"strings"

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
	// This builder only supports builders defined on GitHub.
	return strings.HasPrefix(builderID, "https://cloudbuild.googleapis.com/GoogleHostedWorker@")
}

// Verify provenance.
func (v *GCBVerifier) Verify(ctx context.Context,
	provenance []byte, artifactHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, error) {
	return nil, nil
}
