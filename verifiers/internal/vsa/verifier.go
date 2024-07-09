package vsa

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	sigstoreSignature "github.com/sigstore/sigstore/pkg/signature"
	sigstoreDSSE "github.com/sigstore/sigstore/pkg/signature/dsse"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	vsa10 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/vsa/v1.0"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// VerifyVSA verifies the VSA attestation. It returns the attestation base64-decoded from the envelope, and the trusted attester ID.
// We don't return a TrustedBuilderID. Instead, the user can user can parse the builderID separately, perhaps with
// https://pkg.go.dev/golang.org/x/mod/semver.
func VerifyVSA(ctx context.Context,
	attestation []byte,
	vsaOpts *options.VSAOpts,
	verificationOpts *options.VerificationOpts,
) ([]byte, error) {
	// following steps in https://slsa.dev/spec/v1.1/verification_summary#how-to-verify
	envelope, err := utils.EnvelopeFromBytes(attestation)
	if err != nil {
		return nil, err
	}

	// 1. verify the envelope signature,
	// 4. match the verfier with the public key: implicit because we accept a user-provided public key.
	// 3. parse the VSA, verifying the predicateType.
	vsa, err := extractSignedVSA(ctx, envelope, verificationOpts)
	if err != nil {
		return nil, err
	}

	// 2. match the subject digests,
	// 4. match the verifier ID,
	// 5. match the expected resourceURI,
	// 6. confirm the slsaResult is PASSED,
	// 7. match the verifiedLevels,
	// no other fields are checked.
	err = matchExpectedValues(vsa, vsaOpts)
	if err != nil {
		return nil, err
	}
	vsaBytes, err := envelope.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", serrors.ErrorInvalidDssePayload, err)
	}
	return vsaBytes, nil
}

// extractSignedVSA verifies the envelope signature and type and extracts the VSA from the envelope.
func extractSignedVSA(ctx context.Context, envelope *dsse.Envelope, verificationOpts *options.VerificationOpts) (*vsa10.VSA, error) {
	// 1. verify the envelope signature,
	// 4. match the verfier with the public key: implicit because we accept a user-provided public key.
	err := verifyEnvelopeSignature(ctx, envelope, verificationOpts)
	if err != nil {
		return nil, err
	}
	statement, err := utils.StatementFromEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	// 3. parse the VSA, verifying the predicateType.
	vsa, err := vsa10.VSAFromStatement(statement)
	if err != nil {
		return nil, err
	}
	return vsa, nil
}

// verifyEnvelopeSignature verifies the signature of the envelope.
func verifyEnvelopeSignature(ctx context.Context, envelope *dsse.Envelope, verificationOpts *options.VerificationOpts) error {
	signatureVerifier, err := sigstoreSignature.LoadVerifier(verificationOpts.PublicKey, verificationOpts.PublicKeyHashAlgo)
	if err != nil {
		return fmt.Errorf("%w: loading sigstore DSSE envolope verifier: %w", serrors.ErrorInvalidPublicKey, err)
	}
	envelopeVerifier, err := dsse.NewEnvelopeVerifier(&sigstoreDSSE.VerifierAdapter{
		SignatureVerifier: signatureVerifier,
		Pub:               verificationOpts.PublicKey,
		PubKeyID:          *verificationOpts.PublicKeyID,
	})
	if err != nil {
		return fmt.Errorf("%w: creating sigstore DSSE envelope verifier: %w", serrors.ErrorInvalidPublicKey, err)
	}
	_, err = envelopeVerifier.Verify(ctx, envelope)
	if err != nil {
		return fmt.Errorf("%w: verifying envelope: %w", serrors.ErrorNoValidSignature, err)
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
	// 6. confirm the verificationResult is Passed
	if err := confirmVerificationResult(vsa); err != nil {
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
	if len(*vsaOpts.ExpectedDigests) == 0 {
		return fmt.Errorf("%w: no subject digests provided", serrors.ErrorEmptyRequiredField)
	}
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
	if len(allVSASubjectDigests) == 0 {
		return fmt.Errorf("%w: no subject digests found in the VSA", serrors.ErrorInvalidDssePayload)
	}
	// search for the expected digests in the VSA
	for _, expectedDigest := range *vsaOpts.ExpectedDigests {
		parts := strings.SplitN(expectedDigest, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("%w: expected digest %s is not in the format <digest type>:<digest value>", serrors.ErrorInvalidDssePayload, expectedDigest)
		}
		digestType := parts[0]
		digestValue := parts[1]
		if _, ok := allVSASubjectDigests[digestType]; !ok {
			return fmt.Errorf("%w: expected digest not found: %s", serrors.ErrorMissingSubjectDigest, expectedDigest)
		}
		if _, ok := allVSASubjectDigests[digestType][digestValue]; !ok {
			return fmt.Errorf("%w: expected digest not found: %s", serrors.ErrorMissingSubjectDigest, expectedDigest)
		}
	}
	return nil
}

// matchVerifierID checks if the verifier ID in the VSA matches the expected value.
func matchVerifierID(vsa *vsa10.VSA, vsaOpts *options.VSAOpts) error {
	if vsa.Predicate.Verifier.ID == "" {
		return fmt.Errorf("%w: no verifierID found in the VSA", serrors.ErrorEmptyRequiredField)
	}
	if *vsaOpts.ExpectedVerifierID != vsa.Predicate.Verifier.ID {
		return fmt.Errorf("%w: verifier ID mismatch: wanted %s, got %s", serrors.ErrorMismatchVerifierID, *vsaOpts.ExpectedVerifierID, vsa.Predicate.Verifier.ID)
	}
	return nil
}

// matchResourceURI checks if the resource URI in the VSA matches the expected value.
func matchResourceURI(vsa *vsa10.VSA, vsaOpts *options.VSAOpts) error {
	if vsa.Predicate.ResourceURI == "" {
		return fmt.Errorf("%w: no resourceURI provided", serrors.ErrorEmptyRequiredField)
	}
	if *vsaOpts.ExpectedResourceURI != vsa.Predicate.ResourceURI {
		return fmt.Errorf("%w: resource URI mismatch: wanted %s, got %s", serrors.ErrorMismatchResourceURI, *vsaOpts.ExpectedResourceURI, vsa.Predicate.ResourceURI)
	}
	return nil
}

// confirmVerificationResult checks that the policy verification result is "PASSED".
func confirmVerificationResult(vsa *vsa10.VSA) error {
	if vsa.Predicate.VerificationResult != "PASSED" {
		return fmt.Errorf("%w: verification result is not Passed: %s", serrors.ErrorInvalidVerificationResult, vsa.Predicate.VerificationResult)
	}
	return nil
}

// matchVerifiedLevels checks if the verified levels in the VSA match the expected values.
func matchVerifiedLevels(vsa *vsa10.VSA, vsaOpts *options.VSAOpts) error {
	// check for SLSA track levels
	wantedSLSALevels, err := extractSLSALevels(vsaOpts.ExpectedVerifiedLevels)
	if err != nil {
		return err
	}
	gotSLSALevels, err := extractSLSALevels(&vsa.Predicate.VerifiedLevels)
	if err != nil {
		return err
	}
	for track, expectedMinLSLSALevel := range wantedSLSALevels {
		if vsaLevel, exists := gotSLSALevels[track]; !exists {
			return fmt.Errorf("%w: expected SLSA level not found: %s", serrors.ErrorMismatchVerifiedLevels, track)
		} else if vsaLevel < expectedMinLSLSALevel {
			return fmt.Errorf("%w: expected SLSA level %s to be at least %d, got %d", serrors.ErrorMismatchVerifiedLevels, track, expectedMinLSLSALevel, vsaLevel)
		}
	}

	// check for non-SLSA track levels
	nonSLSAVSALevels := make(map[string]bool)
	for _, level := range vsa.Predicate.VerifiedLevels {
		if isSLSATRACKLevel(level) {
			continue
		}
		nonSLSAVSALevels[level] = true
	}
	for _, expectedLevel := range *vsaOpts.ExpectedVerifiedLevels {
		if isSLSATRACKLevel(expectedLevel) {
			continue
		}
		if _, ok := nonSLSAVSALevels[expectedLevel]; !ok {
			return fmt.Errorf("%w: expected verified level not found: %s", serrors.ErrorMismatchVerifiedLevels, expectedLevel)
		}
	}
	return nil
}

// isSLSATRACKLevel checks if the level is an SLSA track level.
// SLSA track levels are of the form SLSA_<track>_LEVEL_<level>, e.g., SLSA_BUILD_LEVEL_2.
func isSLSATRACKLevel(level string) bool {
	return strings.HasPrefix(level, "SLSA_")
}

// extractSLSALevels extracts the SLSA levels from the verified levels.
// It returns a map of track to the highest level found, e.g.,
// SLSA_BUILD_LEVEL_2, SLSA_SOURCE_LEVEL_3 ->
//
//	{
//		"BUILD": 2,
//		"SOURCE": 3,
//	}
func extractSLSALevels(trackLevels *[]string) (map[string]int, error) {
	vsaSLSATrackLadder := make(map[string]int)
	for _, trackLevel := range *trackLevels {
		if !strings.HasPrefix(trackLevel, "SLSA_") {
			continue
		}
		parts := strings.SplitN(trackLevel, "_", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("%w: invalid SLSA level: %s", serrors.ErrorInvalidSLSALevel, trackLevel)
		}
		if parts[2] != "LEVEL" {
			return nil, fmt.Errorf("%w: invalid SLSA level: %s", serrors.ErrorInvalidSLSALevel, trackLevel)
		}
		track := parts[1]
		level, err := strconv.Atoi(parts[3])
		if err != nil {
			return nil, fmt.Errorf("%w: invalid SLSA level: %s", serrors.ErrorInvalidSLSALevel, trackLevel)
		}
		if currentLevel, exists := vsaSLSATrackLadder[track]; exists {
			vsaSLSATrackLadder[track] = max(currentLevel, level)
		} else {
			vsaSLSATrackLadder[track] = level
		}
	}
	return vsaSLSATrackLadder, nil
}
