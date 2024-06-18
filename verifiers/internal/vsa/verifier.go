package vsa

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	sigstoreBundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sigstoreCryptoUtils "github.com/sigstore/sigstore/pkg/cryptoutils"
	sigstoreSignature "github.com/sigstore/sigstore/pkg/signature"
	sigstoreDSSE "github.com/sigstore/sigstore/pkg/signature/dsse"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	vsaKeys "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/vsa/keys"
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

	// verify the envelope. signature
	err = verifyEnvelopeSignature(ctx, &sigstoreEnvelope)
	if err != nil {
		return nil, nil, err
	}

	// TODO:
	// verify the metadata
	statement, err := utils.StatementFromEnvelope(envelope)
	if err != nil {
		return nil, nil, err
	}
	vsa, err := vsa10.VSAFromStatement(statement)
	if err != nil {
		return nil, nil, err
	}
	err = matchExpectedValues(vsa, vsaOpts)
	if err != nil {
		return nil, nil, err
	}

	// TODO:
	// print the attestation
	return nil, nil, nil
}

// verifyEnvelopeSignature verifies the signatures of the envelope, requiring at least one signature to be valid.
func verifyEnvelopeSignature(ctx context.Context, sigstoreEnvelope *sigstoreBundle.Envelope) error {
	// assemble an "adapter" for each of the signatures and their KeyID
	var verifierAdapters []dsse.Verifier
	for _, signature := range sigstoreEnvelope.Envelope.Signatures {
		keyID := signature.KeyID
		pubKeyString, ok := vsaKeys.AttestorKeys[keyID]
		if !ok {
			continue
		}
		pubKey, err := sigstoreCryptoUtils.UnmarshalPEMToPublicKey([]byte(pubKeyString))
		if err != nil {
			return fmt.Errorf("%w: %w", serrors.ErrorInvalidPublicKey, err)
		}
		signatureVerifier, err := sigstoreSignature.LoadVerifier(pubKey, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("%w: loading sigstore DSSE envolope verifier %w", serrors.ErrorInvalidPublicKey, err)
		}
		verifierAdapter := &sigstoreDSSE.VerifierAdapter{
			SignatureVerifier: signatureVerifier,
			Pub:               pubKey,
			PubKeyID:          keyID, // "keystore://76574:prod:vsa_signing_public_key"
		}
		verifierAdapters = append(verifierAdapters, verifierAdapter)
	}
	// create the envelope verifier with all adapters
	envelopeVerifier, err := dsse.NewEnvelopeVerifier(verifierAdapters...)
	if err != nil {
		return fmt.Errorf("%w: creating sigstore DSSE envelope verifier %w", serrors.ErrorInvalidPublicKey, err)
	}
	// verify the envelope
	_, err = envelopeVerifier.Verify(ctx, sigstoreEnvelope.Envelope)
	if err != nil {
		return fmt.Errorf("%w: verifying envelope %w", serrors.ErrorInvalidPublicKey, err)
	}
	return nil
}

// matchExpectedValues checks if the expected values are present in the VSA.
func matchExpectedValues(vsa *vsa10.VSA, vsaOpts *options.VSAOpts) error {
	if err := matchExepectedSubjectDigests(vsa, vsaOpts); err != nil {
		return err
	}
	// TODO: match other expected values
	return nil
}

// matchExepectedSubjectDigests checks if the expected subject digests are present in the VSA.
func matchExepectedSubjectDigests(vsa *vsa10.VSA, vsaOpts *options.VSAOpts) error {
	// collect all digests from the VSA, so we can efficiently search, e.g.:
	// {
	// 	"sha256": {
	// 		"abc": true,
	// 		"def": true,
	// 	},
	// 	"gce_image_id": {
	// 		"123": true,
	// 		"456": true,
	// 	}
	// }
	allVSASubjectDigests := make(map[string]map[string]bool)
	for _, subject := range vsa.Subject {
		for digestType, digestValue := range subject.Digest {
			if _, ok := allVSASubjectDigests[digestType]; !ok {
				allVSASubjectDigests[digestType] = make(map[string]bool)
			}
			allVSASubjectDigests[digestType][digestValue] = true
		}
	}
	// search for the expected digests in the VSA
	for _, expectedDigest := range vsaOpts.ExpectedDigests {
		parts := strings.SplitN(expectedDigest, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("%w: expected digest %s is not in the format <digest type>:<digest value>", serrors.ErrorInvalidDssePayload, expectedDigest)
		}
		digestType := parts[0]
		digestValue := parts[1]
		if _, ok := allVSASubjectDigests[digestType]; !ok {
			return fmt.Errorf("%w: expected digest not found: %s", serrors.ErrorInvalidDssePayload, expectedDigest)
		}
		if _, ok := allVSASubjectDigests[digestType][digestValue]; !ok {
			return fmt.Errorf("%w: expected digest not found: %s", serrors.ErrorInvalidDssePayload, expectedDigest)
		}
	}
	return nil
}
