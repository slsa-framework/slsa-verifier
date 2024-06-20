package vsa

import (
	"context"
	"fmt"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	sigstoreBundle "github.com/sigstore/sigstore-go/pkg/bundle"
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
	verificationOpts *options.VerificationOpts,
) ([]byte, *utils.TrustedAttesterID, error) {
	// following steps in https://slsa.dev/spec/v1.1/verification_summary#how-to-verify

	// parse the envelope
	envelope, err := utils.EnvelopeFromBytes(attestations)
	if err != nil {
		return nil, nil, err
	}
	sigstoreEnvelope := sigstoreBundle.Envelope{
		Envelope: envelope,
	}

	// 1. verify the envelope signature,
	// 4. match the verfier with the public key: implicit because we accept a user-provided public key.
	err = verifyEnvelopeSignature(ctx, &sigstoreEnvelope, verificationOpts)
	if err != nil {
		return nil, nil, err
	}

	statement, err := utils.StatementFromEnvelope(envelope)
	if err != nil {
		return nil, nil, err
	}
	// 3. parse the VSA, verifying the predicateType.
	vsa, err := vsa10.VSAFromStatement(statement)
	if err != nil {
		return nil, nil, err
	}

	// 2. match the subject digests,
	// 4. match the verifier ID,
	// 5. match the expected valuesmatch resourceURI,
	// 6. confirm the slsaResult is PASSED,
	// 7. match the verifiedLevels,
	// no other feields are checked.
	err = matchExpectedValues(vsa, vsaOpts)
	if err != nil {
		return nil, nil, err
	}
	trustedAttesterID, err := utils.TrustedAttesterIDNew(vsa.Predicate.Verifier.ID, false)
	if err != nil {
		return nil, nil, err
	}
	vsaBytes, err := envelope.DecodeB64Payload()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", serrors.ErrorInvalidDssePayload, err)
	}
	return vsaBytes, trustedAttesterID, nil
}

// verifyEnvelopeSignature verifies the signature of the envelope.
func verifyEnvelopeSignature(ctx context.Context, sigstoreEnvelope *sigstoreBundle.Envelope, verificationOpts *options.VerificationOpts) error {
	signatureVerifier, err := sigstoreSignature.LoadVerifier(verificationOpts.PublicKey, verificationOpts.PublicKeyHashAlgo)
	if err != nil {
		return fmt.Errorf("%w: loading sigstore DSSE envolope verifier %w", serrors.ErrorInvalidPublicKey, err)
	}
	envelopeVerifier, err := dsse.NewEnvelopeVerifier(&sigstoreDSSE.VerifierAdapter{
		SignatureVerifier: signatureVerifier,
		Pub:               verificationOpts.PublicKey,
		PubKeyID:          verificationOpts.PublicKeyID,
	})
	if err != nil {
		return fmt.Errorf("%w: creating sigstore DSSE envelope verifier %w", serrors.ErrorInvalidPublicKey, err)
	}
	_, err = envelopeVerifier.Verify(ctx, sigstoreEnvelope.Envelope)
	if err != nil {
		return fmt.Errorf("%w: verifying envelope %w", serrors.ErrorInvalidPublicKey, err)
	}
	return nil
}

// matchExpectedValues checks if the expected values are present in the VSA.
func matchExpectedValues(vsa *vsa10.VSA, vsaOpts *options.VSAOpts) error {
	// 2. match the expected subject digests
	if err := matchExepectedSubjectDigests(vsa, vsaOpts); err != nil {
		return err
	}
	// 4. match the verifier ID
	if err := matchVerifierID(vsa, vsaOpts); err != nil {
		return err
	}
	// 5. match the expected resourceURI
	if err := matchResourceURI(vsa, vsaOpts); err != nil {
		return err
	}
	// 6. confirm the slsaResult is Passed
	if err := conirmSLASResult(vsa); err != nil {
		return err
	}
	// 7. match the verifiedLevels
	if err := matchVerifiedLevels(vsa, vsaOpts); err != nil {
		return err
	}
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

// matchVerifierID checks if the verifier ID in the VSA matches the expected value.
func matchVerifierID(vsa *vsa10.VSA, vsaOpts *options.VSAOpts) error {
	if vsa.Predicate.Verifier.ID != vsaOpts.ExpectedVerifierID {
		return fmt.Errorf("%w: verifier ID mismatch: expected %s, got %s", serrors.ErrorInvalidDssePayload, vsa.Predicate.Verifier.ID, vsa.Predicate.Verifier.ID)
	}
	return nil
}

// matchResourceURI checks if the resource URI in the VSA matches the expected value.
func matchResourceURI(vsa *vsa10.VSA, vsaOpts *options.VSAOpts) error {
	if vsa.Predicate.ResourceURI != vsaOpts.ExpectedResourceURI {
		return fmt.Errorf("%w: resource URI mismatch: expected %s, got %s", serrors.ErrorInvalidDssePayload, vsa.Predicate.ResourceURI, vsaOpts.ExpectedResourceURI)
	}
	return nil
}

// confirmSLASResult confirms the VSA verification result is PASSED.
func conirmSLASResult(vsa *vsa10.VSA) error {
	if normalizeString(vsa.Predicate.VerificationResult) != "PASSED" {
		return fmt.Errorf("%w: verification result is not Passed: %s", serrors.ErrorInvalidDssePayload, vsa.Predicate.VerificationResult)
	}
	return nil
}

// matchVerifiedLevels checks if the verified levels in the VSA match the expected values.
func matchVerifiedLevels(vsa *vsa10.VSA, vsaOpts *options.VSAOpts) error {
	vsaLevels := make(map[string]bool)
	for _, level := range vsa.Predicate.VerifiedLevels {
		vsaLevels[level] = true
	}
	for _, expectedLevel := range vsaOpts.ExpectedVerifiedLevels {
		if _, ok := vsaLevels[normalizeString(expectedLevel)]; !ok {
			return fmt.Errorf("%w: expected verified level not found: %s", serrors.ErrorInvalidDssePayload, expectedLevel)
		}
	}
	return nil
}

// normalizeString normalizes a string by trimming whitespace and converting to uppercase.
func normalizeString(s string) string {
	return strings.TrimSpace(strings.ToUpper(s))
}
