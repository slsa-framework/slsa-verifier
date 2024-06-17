package vsa

import (
	"context"
	"fmt"

	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// VerifyVSA verifies the VSA attestations.
func VerifyVSA(ctx context.Context,
	attestations []byte,
	vsaOpts *options.VSAOpts,
) ([]byte, *utils.TrustedAttesterID, error) {
	// parse the envelope
	envelope, err := utils.EnvelopeFromBytes(attestations)
	if err != nil {
		return nil, nil, err
	}
	fmt.Println(envelope)
	// verify the envelope. signature
	// verify the metadata
	// print the attestation
	return nil, nil, nil
}
