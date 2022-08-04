package register

import (
	"context"

	"github.com/slsa-framework/slsa-verifier/options"
)

var SLSAVerifiers = make(map[string]SLSAVerifier)

type SLSAVerifier interface {
	// Match matches a BuilderID.
	Match(builderID string) bool

	// Verify verifies a provenance.
	Verify(ctx context.Context,
		provenance []byte, artifactHash string,
		provenanceOpts *options.ProvenanceOpts,
		builderOpts *options.BuilderOpts,
	) ([]byte, error)
}

func RegisterVerifier(name string, verifier SLSAVerifier) {
	SLSAVerifiers[name] = verifier
}
