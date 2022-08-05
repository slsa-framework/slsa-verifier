package gha

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/slsa-framework/slsa-verifier/options"
	"github.com/slsa-framework/slsa-verifier/register"
)

const VerifierName = "GHA"

//nolint:gochecknoinits
func init() {
	register.RegisterVerifier(VerifierName, GHAVerifierNew())
}

type GHAVerifier struct{}

func GHAVerifierNew() *GHAVerifier {
	return &GHAVerifier{}
}

// Match a BuilderID.
func (v *GHAVerifier) Match(builderID string) bool {
	// This verifier only supports builders defined on GitHub.
	return strings.HasPrefix(builderID, "https://github.com/")
}

// VerifyArtifact verifies provenance for an artifact.
func (v *GHAVerifier) VerifyArtifact(ctx context.Context,
	provenance []byte, artifactHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, string, error) {
	rClient, err := rekor.NewClient(defaultRekorAddr)
	if err != nil {
		return nil, "", err
	}

	/* Verify signature on the intoto attestation. */
	env, cert, err := VerifyProvenanceSignature(ctx, rClient, provenance, artifactHash)
	if err != nil {
		return nil, "", err
	}

	/* Verify properties of the signing identity. */
	// Get the workflow info given the certificate information.
	workflowInfo, err := GetWorkflowInfoFromCertificate(cert)
	if err != nil {
		return nil, "", err
	}

	// Verify the workflow identity.
	builderID, err := VerifyWorkflowIdentity(workflowInfo, builderOpts,
		provenanceOpts.ExpectedSourceURI)
	if err != nil {
		return nil, "", err
	}

	/* Verify properties of the SLSA provenance. */
	// Unpack and verify info in the provenance, including the Subject Digest.
	provenanceOpts.ExpectedBuilderID = builderID
	if err := VerifyProvenance(env, provenanceOpts); err != nil {
		return nil, "", err
	}

	fmt.Fprintf(os.Stderr, "Verified build using builder https://github.com%s at commit %s\n",
		workflowInfo.JobWobWorkflowRef,
		workflowInfo.CallerHash)
	// Return verified provenance.
	r, err := base64.StdEncoding.DecodeString(env.Payload)
	return r, builderID, err
}

// VerifyImage verifies provenance for an OCI image.
func (v *GHAVerifier) VerifyImage(ctx context.Context,
	provenance []byte, artifactHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, string, error) {
	return nil, "todo", serrors.ErrorNotSupported
}
