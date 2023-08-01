package gha

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"

	"github.com/slsa-framework/slsa-github-generator/signing/envelope"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// SignedAttestation contains a signed DSSE envelope
// and its associated signing certificate.
type SignedAttestation struct {
	// The signed DSSE envelope
	Envelope *dsselib.Envelope
	// The signing certificate
	SigningCert *x509.Certificate
	// The associated verified Rekor entry
	RekorEntry *models.LogEntryAnon
}

// EnvelopeFromBytes reads a DSSE envelope from the given payload.
func EnvelopeFromBytes(payload []byte) (env *dsselib.Envelope, err error) {
	env = &dsselib.Envelope{}
	err = json.Unmarshal(payload, env)
	return
}

// Verify Builder ID in provenance statement.
// This function does an exact comparison, and expects expectedBuilderID to be the full
// `name@refs/tags/<name>`.
func verifyBuilderIDExactMatch(prov iface.Provenance, expectedBuilderID string) error {
	id, err := prov.BuilderID()
	if err != nil {
		return err
	}
	provBuilderID, err := utils.TrustedBuilderIDNew(id, false)
	if err != nil {
		return err
	}

	if err := provBuilderID.MatchesFull(expectedBuilderID, true); err != nil {
		return err
	}
	return nil
}

// Inputs value in place of --BuilderID for builders of ExpectedPath such that the builderID for
// the builders do not need to be inputted. Example: the expectedBuilderID will default to
// the delegator builder ID for BYOB, this can verify actual BYOB builder for user without --builder-id flag.
// Currently slsa-framework path is the only one supported for ExpectedBuilderPath.
func verifyBuilderIDPath(prov iface.Provenance, expectedBuilderIDPath string) (string, error) {
	id, err := prov.BuilderID()
	if err != nil {
		return "", err
	}

	provBuilderID, err := utils.TrustedBuilderIDNew(id, false)
	if err != nil {
		return "", err
	}

	// Compare actual BuilderIDPath with the expected
	if !strings.HasPrefix(provBuilderID.Name(), expectedBuilderIDPath) {
		return "", fmt.Errorf("%w: BuilderID Path Mismatch. Got: %q. Expected: %q", serrors.ErrorInvalidBuilderID, provBuilderID.Name(), expectedBuilderIDPath)
	}

	return provBuilderID.Name(), nil
}

// Verify Builder ID in provenance statement.
// This function verifies the names match. If the expected builder ID contains a version,
// it also verifies the versions match.
func verifyBuilderIDLooseMatch(prov iface.Provenance, expectedBuilderID string) error {
	id, err := prov.BuilderID()
	if err != nil {
		return err
	}
	provBuilderID, err := utils.TrustedBuilderIDNew(id, false)
	if err != nil {
		return err
	}

	if err := provBuilderID.MatchesLoose(expectedBuilderID, true); err != nil {
		return err
	}
	return nil
}

// Verify source URI in provenance statement.
func verifySourceURI(prov iface.Provenance, expectedSourceURI string) error {
	source := utils.NormalizeGitURI(expectedSourceURI)

	// We expect github.com URIs only.
	if !strings.HasPrefix(source, "git+https://github.com/") {
		return fmt.Errorf("%w: expected source github.com repository %q", serrors.ErrorMalformedURI,
			source)
	}

	// Verify source in the trigger
	fullTriggerURI, err := prov.TriggerURI()
	if err != nil {
		return err
	}

	triggerURI, triggerRef, err := utils.ParseGitURIAndRef(fullTriggerURI)
	if err != nil {
		return err
	}
	if triggerURI != source {
		return fmt.Errorf("%w: expected trigger %q to match source-uri %q", serrors.ErrorMismatchSource,
			source, fullTriggerURI)
	}
	// We expect the trigger URI to always have a ref.
	if triggerRef == "" {
		return fmt.Errorf("%w: missing ref: %q", serrors.ErrorMalformedURI, fullTriggerURI)
	}

	// Verify source from material section.
	fullSourceURI, err := prov.SourceURI()
	if err != nil {
		return err
	}

	sourceURI, sourceRef, err := utils.ParseGitURIAndRef(fullSourceURI)
	if err != nil {
		return err
	}
	if sourceURI != source {
		return fmt.Errorf("%w: expected source %q to match source-uri %q", serrors.ErrorMismatchSource,
			fullSourceURI, source)
	}

	buildType, err := prov.BuildType()
	if err != nil {
		return fmt.Errorf("checking buildType: %v", err)
	}
	if sourceRef == "" {
		// NOTE: this is an exception for npm packages built before GA,
		// see https://github.com/slsa-framework/slsa-verifier/issues/492.
		// We don't need to compare the ref since materialSourceURI does not contain it.
		if buildType == common.NpmCLIBuildTypeV1 {
			return nil
		}
		// NOTE: BYOB builders can build from a different ref than the triggering ref.
		// This most often happens when a TRW makes a commit as part of the release process.
		// NOTE: Currently only building from a different git sha is supported
		// which means the sourceRef is empty. Building from an arbitrary ref
		// is currently not supported.
		if buildType == common.BYOBBuildTypeV0 {
			return nil
		}
		return fmt.Errorf("%w: missing ref: %q", serrors.ErrorMalformedURI, fullSourceURI)
	}

	// Last, verify that both fields match. We expect that the trigger URI and
	// the source URI match but the ref used to trigger the build and source ref
	// could be different.
	if fullTriggerURI != fullSourceURI {
		return fmt.Errorf("%w: source and trigger URIs do not match: %q != %q",
			serrors.ErrorInvalidDssePayload,
			fullTriggerURI, fullSourceURI)
	}

	return nil
}

// Verify Subject Digest from the provenance statement.
func verifyDigest(prov iface.Provenance, expectedHash string) error {
	subjects, err := prov.Subjects()
	if err != nil {
		return err
	}

	// 8 bit represented in hex, so 8/2=4.
	bitLength := len(expectedHash) * 4
	expectedAlgo := fmt.Sprintf("sha%v", bitLength)
	if bitLength < 256 {
		return fmt.Errorf("%w: expected minimum 256-bit. Got %d", serrors.ErrorInvalidHash, bitLength)
	}

	for _, subject := range subjects {
		digestSet := subject.Digest
		hash, exists := digestSet[expectedAlgo]
		if !exists {
			continue
		}
		if hash == expectedHash {
			return nil
		}
	}

	return fmt.Errorf("expected hash '%s' not found: %w", expectedHash, serrors.ErrorMismatchHash)
}

// VerifyProvenanceSignature returns the verified DSSE envelope containing the provenance
// and the signing certificate given the provenance and artifact hash.
func VerifyProvenanceSignature(ctx context.Context, trustedRoot *TrustedRoot,
	rClient *client.Rekor,
	provenance []byte, artifactHash string) (
	*SignedAttestation, error,
) {
	// There are two cases, either we have an embedded certificate, or we need
	// to use the Redis index for searching by artifact SHA.
	if hasCertInEnvelope(provenance) {
		// Get Rekor entries corresponding to provenance
		return GetValidSignedAttestationWithCert(rClient, provenance, trustedRoot)
	}

	// Fallback on using the redis search index to get matching UUIDs.
	fmt.Fprintf(os.Stderr, "No certificate provided, trying Redis search index to find entries by subject digest\n")

	// Verify the provenance and return the signing certificate.
	return SearchValidSignedAttestation(ctx, artifactHash,
		provenance, rClient, trustedRoot)
}

// VerifyNpmPackageProvenance verifies provenance for an npm package.
func VerifyNpmPackageProvenance(env *dsselib.Envelope, workflow *WorkflowIdentity,
	provenanceOpts *options.ProvenanceOpts, trustedBuilderID *utils.TrustedBuilderID, isTrustedBuilder bool,
) error {
	prov, err := slsaprovenance.ProvenanceFromEnvelope(trustedBuilderID.Name(), env)
	if err != nil {
		return err
	}

	// TODO: Verify the buildType.
	// This depends on the builder (delegator or CLI).

	// Verify the builder ID.
	if err := verifyBuilderIDLooseMatch(prov, provenanceOpts.ExpectedBuilderID); err != nil {
		// Verification failed. Try again by appending or removing the the hosted status.
		// Older provenance uses the shorted version without status, and recent provenance includes the status.
		// We consider the short version witout status as github-hosted.
		switch {
		case !strings.HasSuffix(provenanceOpts.ExpectedBuilderID, "/"+string(hostedGitHub)):
			// Append the status.
			bid := provenanceOpts.ExpectedBuilderID + "/" + string(hostedGitHub)
			oerr := verifyBuilderIDLooseMatch(prov, bid)
			if oerr != nil {
				// We do return the original error, since that's the caller the user provided.
				return err
			}
			// Verification success.
			err = nil

		case strings.HasSuffix(provenanceOpts.ExpectedBuilderID, "/"+string(hostedGitHub)):
			// Remove the status.
			bid := strings.TrimSuffix(provenanceOpts.ExpectedBuilderID, "/"+string(hostedGitHub))
			oerr := verifyBuilderIDLooseMatch(prov, bid)
			if oerr != nil {
				// We do return the original error, since that's the caller the user provided.
				return err
			}
			// Verification success.
			err = nil

		default:
			break
		}

		if err != nil {
			return err
		}
	}

	// Also, the GitHub context is not recorded for the default builder.
	if err := VerifyProvenanceCommonOptions(prov, provenanceOpts); err != nil {
		return err
	}

	// Verify consistency between the provenance and the certificate.
	// because for the non trusted builders, the information may be forgeable.
	if !isTrustedBuilder {
		return verifyProvenanceMatchesCertificate(prov, workflow)
	}
	return nil
}

func isValidDelegatorBuilderID(prov iface.Provenance) error {
	// Verify the TRW was referenced at a proper tag by the user.
	id, err := prov.BuilderID()
	if err != nil {
		return err
	}
	parts := strings.Split(id, "@")
	if len(parts) != 2 {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidBuilderID, id)
	}

	// Exception for JReleaser builders.
	// See https://github.com/slsa-framework/slsa-github-generator/issues/2035#issuecomment-1579963802.
	if strings.HasPrefix(parts[0], JReleaserRepository) {
		return utils.IsValidJreleaserBuilderTag(parts[1])
	}
	return utils.IsValidBuilderTag(parts[1], false)
}

// VerifyProvenance verifies the provenance for the given DSSE envelope.
func VerifyProvenance(env *dsselib.Envelope, provenanceOpts *options.ProvenanceOpts, trustedBuilderID *utils.TrustedBuilderID, byob bool,
	builderOpts *options.BuilderOpts) error {
	prov, err := slsaprovenance.ProvenanceFromEnvelope(trustedBuilderID.Name(), env)
	if err != nil {
		return err
	}

	// Verify Builder ID.
	if byob {
		if err := isValidDelegatorBuilderID(prov); err != nil {
			return err
		}

		// If ExpectedID is empty, check to see if it is a trusted builder
		if builderOpts.ExpectedID == nil || *builderOpts.ExpectedID == "" {
			var trustedBuilderRepositoryPath = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/"
			if provenanceOpts.ExpectedBuilderID, err = verifyBuilderIDPath(prov, trustedBuilderRepositoryPath); err != nil {
				return err
			}
		}

		// Note: `provenanceOpts.ExpectedBuilderID` is provided by the user
		// or from return of verifyBuilderIDPath.
		if err := verifyBuilderIDLooseMatch(prov, provenanceOpts.ExpectedBuilderID); err != nil {
			return err
		}
	} else {
		// Note: `provenanceOpts.ExpectedBuilderID` is not provided by the user,
		// but taken from the certificate. It always is of the form `name@refs/tags/<name>`.
		if err := verifyBuilderIDExactMatch(prov, provenanceOpts.ExpectedBuilderID); err != nil {
			return err
		}
	}

	return VerifyProvenanceCommonOptions(prov, provenanceOpts)
}

// VerifyProvenanceCommonOptions verifies the given provenance.
func VerifyProvenanceCommonOptions(prov iface.Provenance, provenanceOpts *options.ProvenanceOpts) error {
	// Verify source.
	if err := verifySourceURI(prov, provenanceOpts.ExpectedSourceURI); err != nil {
		return err
	}

	// Verify subject digest.
	if err := verifyDigest(prov, provenanceOpts.ExpectedDigest); err != nil {
		return err
	}

	// Verify the branch.
	if provenanceOpts.ExpectedBranch != nil {
		if err := VerifyBranch(prov, *provenanceOpts.ExpectedBranch); err != nil {
			return err
		}
	}

	// Verify the tag.
	if provenanceOpts.ExpectedTag != nil {
		if err := VerifyTag(prov, *provenanceOpts.ExpectedTag); err != nil {
			return err
		}
	}

	// Verify the versioned tag.
	if provenanceOpts.ExpectedVersionedTag != nil {
		if err := VerifyVersionedTag(prov, *provenanceOpts.ExpectedVersionedTag); err != nil {
			return err
		}
	}

	// Verify the workflow inputs.
	if len(provenanceOpts.ExpectedWorkflowInputs) > 0 {
		if err := VerifyWorkflowInputs(prov, provenanceOpts.ExpectedWorkflowInputs); err != nil {
			return err
		}
	}

	return nil
}

// VerifyWorkflowInputs verifies that the workflow inputs in the provenance
// match the expected values.
func VerifyWorkflowInputs(prov iface.Provenance, inputs map[string]string) error {
	pyldInputs, err := prov.GetWorkflowInputs()
	if err != nil {
		return err
	}

	// Verify all inputs.
	for k, v := range inputs {
		value, err := common.GetAsString(pyldInputs, k)
		if err != nil {
			return fmt.Errorf("%w: cannot retrieve value of '%s'", serrors.ErrorMismatchWorkflowInputs, k)
		}

		if v != value {
			return fmt.Errorf("%w: expected '%s=%s', got '%s=%s'",
				serrors.ErrorMismatchWorkflowInputs, k, v, k, value)
		}
	}

	return nil
}

// VerifyBranch verifies that the source branch in the provenance matches the
// expected value.
func VerifyBranch(prov iface.Provenance, expectedBranch string) error {
	ref, err := prov.GetBranch()
	if err != nil {
		return err
	}

	branch, err := utils.BranchFromGitRef(ref)
	if err != nil {
		return fmt.Errorf("verifying branch: %w", err)
	}

	if branch != expectedBranch {
		return fmt.Errorf("expected branch '%s', got '%s': %w", expectedBranch, branch, serrors.ErrorMismatchBranch)
	}

	return nil
}

// VerifyTag verifies that the source tag in the provenance matches the
// expected value.
func VerifyTag(prov iface.Provenance, expectedTag string) error {
	ref, err := prov.GetTag()
	if err != nil {
		return err
	}

	tag, err := utils.TagFromGitRef(ref)
	if err != nil {
		return fmt.Errorf("verifying tag: %w", err)
	}

	if tag != expectedTag {
		return fmt.Errorf("expected tag '%s', got '%s': %w", expectedTag, tag, serrors.ErrorMismatchTag)
	}

	return nil
}

// VerifyVersionedTag verifies that the source tag in the provenance matches the
// expected semver value.
func VerifyVersionedTag(prov iface.Provenance, expectedTag string) error {
	// Retrieve, validate and canonicalize the provenance tag.
	// Note: prerelease is validated as part of patch validation
	// and must be equal. Build is discarded as per https://semver.org/:
	// "Build metadata MUST be ignored when determining version precedence",
	ref, err := prov.GetTag()
	if err != nil {
		return err
	}

	tag, err := utils.TagFromGitRef(ref)
	if err != nil {
		return fmt.Errorf("verifying tag: %w", err)
	}

	return utils.VerifyVersionedTag(tag, expectedTag)
}

// hasCertInEnvelope checks if a valid x509 certificate is present in the
// envelope.
func hasCertInEnvelope(provenance []byte) bool {
	certPem, err := envelope.GetCertFromEnvelope(provenance)
	return err == nil && len(certPem) > 0
}
