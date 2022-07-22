package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/slsa-framework/slsa-verifier/verification"
)

var defaultRekorAddr = "https://rekor.sigstore.dev"

func Verify(ctx context.Context,
	provenance []byte, artifactHash, source string, provenanceOpts *verification.ProvenanceOpts,
) ([]byte, error) {
	rClient, err := rekor.NewClient(defaultRekorAddr)
	if err != nil {
		return nil, err
	}

	/* Verify signature on the intoto attestation. */
	env, cert, err := verification.VerifyProvenanceSignature(ctx, rClient, provenance, artifactHash)
	if err != nil {
		return nil, err
	}

	/* Verify properties of the signing identity. */
	// Get the workflow info given the certificate information.
	workflowInfo, err := verification.GetWorkflowInfoFromCertificate(cert)
	if err != nil {
		return nil, err
	}

	// Verify the workflow identity.
	if err := verification.VerifyWorkflowIdentity(workflowInfo, source); err != nil {
		return nil, err
	}

	/* Verify properties of the SLSA provenance. */
	// Unpack and verify info in the provenance, including the Subject Digest.
	if err := verification.VerifyProvenance(env, provenanceOpts); err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "Verified build using builder https://github.com%s at commit %s\n",
		workflowInfo.JobWobWorkflowRef,
		workflowInfo.CallerHash)
	// Return verified provenance.
	return base64.StdEncoding.DecodeString(env.Payload)
}
