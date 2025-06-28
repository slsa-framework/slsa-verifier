package options

import (
	"crypto"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// ProvenanceOpts are the options for checking provenance information.
type ProvenanceOpts struct {
	// ExpectedBranch is the expected branch (github_ref or github_base_ref) in
	// the invocation parameters.
	ExpectedBranch *string

	// ExpectedTag is the expected tag, github_ref, in the invocation parameters.
	ExpectedTag *string

	// ExpectedVersionedTag is the expected versioned tag.
	ExpectedVersionedTag *string

	// ExpectedDigest is the expected artifact sha included in the provenance.
	ExpectedDigest string

	// ExpectedSourceURI is the expected source URI in the provenance.
	ExpectedSourceURI string

	// ExpectedBuilderID is the expected builder ID that is passed from user and verified
	ExpectedBuilderID string

	// ExpectedWorkflowInputs is a map of key=value inputs.
	ExpectedWorkflowInputs map[string]string

	ExpectedPackageName *string

	ExpectedPackageVersion *string

	// ExpectedProvenanceRepository is the provenance repository that is passed from user.
	ExpectedProvenanceRepository *string
}

// BuildOpts are the options for checking the builder.
type BuilderOpts struct {
	// ExpectedBuilderID is the builderID passed in from the user.
	ExpectedID *string
}

// VSAOpts are the options for checking the VSA.
type VSAOpts struct {
	// ExpectedDigests are the digests expected to be in the VSA.
	ExpectedDigests *[]string

	// ExpectedVerifierID is the verifier ID that is passed from user.
	ExpectedVerifierID *string

	// ExpectedResourceURI is the resource URI that is passed from user.
	ExpectedResourceURI *string

	// ExpectedVerifiedLevels is the levels of verification that are passed from user.
	ExpectedVerifiedLevels *[]string
}

type VerificationOpts struct {
	// PublicKey is the public key used to verify the signature on the Envelope.
	PublicKey crypto.PublicKey

	// PublicKeyID is the ID of the public key.
	PublicKeyID *string

	// PublicKeyHashAlgo is the hash algorithm used to compute digest that was signed.
	PublicKeyHashAlgo crypto.Hash
}

// ClientOpts contain clinets to be used by slsa-verifier.
// In the future, this can include a logger and a rekor client.
type ClientOpts struct {
	// SigstoreTufClient is the Sigstore TUF client, used for retrieving the Npmjs public keys
	SigstoreTUFClient utils.SigstoreTUFClient
}

// NewDefaultClientOpts returns default clients to be used by slsa-verifier.
func NewDefaultClientOpts() (*ClientOpts, error) {
	sigstoreTUFClient, err := utils.GetDefaultSigstoreTUFClient()
	if err != nil {
		return nil, err
	}
	opts := &ClientOpts{
		SigstoreTUFClient: sigstoreTUFClient,
	}
	return opts, nil
}
