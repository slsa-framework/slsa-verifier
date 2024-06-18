package vsa

import (
	"context"
	"crypto"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	sigstoreBundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sigstoreCryptoUtils "github.com/sigstore/sigstore/pkg/cryptoutils"
	sigstoreSignature "github.com/sigstore/sigstore/pkg/signature"
	sigstoreDSSE "github.com/sigstore/sigstore/pkg/signature/dsse"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	vsa10 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/vsa/v1.0"
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
	sigstoreEnvelope := sigstoreBundle.Envelope{
		Envelope: envelope,
	}
	sigstoreStatement, err := sigstoreEnvelope.Statement()
	if err != nil {
		return nil, nil, err
	}
	vsa, err := vsa10.VSAFromStatement(sigstoreStatement)
	if err != nil {
		return nil, nil, err
	}

	// verify the envelope. signature
	err = verifyEnvelopeSignature(ctx, &sigstoreEnvelope)
	if err != nil {
		return nil, nil, err
	}

	// TODO:
	// verify the metadata
	err = matchExpectedValues(vsa, vsaOpts)
	if err != nil {
		return nil, nil, err
	}

	// TODO:
	// print the attestation
	return nil, nil, nil
}

func verifyEnvelopeSignature(ctx context.Context, sigstoreEnvelope *sigstoreBundle.Envelope) error {
	pubKeyBytes := []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeGa6ZCZn0q6WpaUwJrSk+PPYEsca
3Xkk3UrxvbQtoZzTmq0zIYq+4QQl0YBedSyy+XcwAMaUWTouTrB05WhYtg==
-----END PUBLIC KEY-----`)
	pubKey, err := sigstoreCryptoUtils.UnmarshalPEMToPublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("%w: %w", serrors.ErrorInvalidPublicKey, err)
	}
	signatureVerifier, err := sigstoreSignature.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("%w: loading sigstore DSSE envolope verifier %w", serrors.ErrorInvalidPublicKey, err)
	}
	envelopeVerifier, err := dsse.NewEnvelopeVerifier(&sigstoreDSSE.VerifierAdapter{
		SignatureVerifier: signatureVerifier,
		Pub:               pubKey,
	})
	if err != nil {
		return fmt.Errorf("%w: creating verifier %w", serrors.ErrorInvalidPublicKey, err)
	}
	_, err = envelopeVerifier.Verify(ctx, sigstoreEnvelope.Envelope)
	if err != nil {
		return fmt.Errorf("%w: verifying envelope %w", serrors.ErrorInvalidPublicKey, err)
	}
	return nil
}

func matchExpectedValues(vsa *vsa10.VSA, vsaOpts *options.VSAOpts) error {
	// TODO: implement this function
	return nil
}
