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
	sigstoreRoot "github.com/sigstore/sigstore-go/pkg/root"

	proto_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
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
	// The Public Key in the Bundle's VerificationMaterial
	PublicKey *proto_v1.PublicKeyIdentifier
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

// verifyBuilderIDPathPrefix verifies that the builder ID in provenance matches the provided expectedBuilderIDPathPrefix.
// Returns provenance builderID if verified against provided expected Builder ID path prefix.
func verifyBuilderIDPathPrefix(prov iface.Provenance, expectedBuilderIDPathPrefix string) (string, error) {
	id, err := prov.BuilderID()
	if err != nil {
		return "", err
	}

	provBuilderID, err := utils.TrustedBuilderIDNew(id, false)
	if err != nil {
		return "", err
	}

	// Compare actual BuilderID with the expected BuilderID Path Prefix.
	if !strings.HasPrefix(provBuilderID.Name(), expectedBuilderIDPathPrefix) {
		return "", fmt.Errorf("%w: BuilderID Path Mismatch. Got: %q. Expected BuilderID Path Prefix: %q", serrors.ErrorInvalidBuilderID, provBuilderID.Name(), expectedBuilderIDPathPrefix)
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
func VerifyProvenanceSignature(ctx context.Context, trustedRoot *sigstoreRoot.LiveTrustedRoot,
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
	builderRef := parts[1]

	// Exception for JReleaser builders.
	// See https://github.com/slsa-framework/slsa-github-generator/issues/2035#issuecomment-1579963802.
	if strings.HasPrefix(parts[0], JReleaserRepository) {
		return utils.IsValidJreleaserBuilderTag(builderRef)
	}

	sourceURI, err := prov.SourceURI()
	if err != nil {
		return err
	}

	uri, _, err := utils.ParseGitURIAndRef(sourceURI)
	if err != nil {
		return err
	}
	// Exception to enable e2e tests for BYOB builders referenced at main.
	normalizedE2eRepoURI := utils.NormalizeGitURI(httpsGithubCom + e2eTestRepository)
	normalizedURI := utils.NormalizeGitURI(uri)
	if normalizedURI == normalizedE2eRepoURI && options.TestingEnabled() {
		// Allow verification on the main branch to support e2e tests.
		if builderRef == "refs/heads/main" {
			return nil
		}
	}

	// Exception for slsa-framework/slsa-github-generator branches during testing mode
	// to allow provenance from non-main to be verified, such as during development.
	normalizedSLSAGithubGeneratorRepoURI := utils.NormalizeGitURI(httpsGithubCom + trustedBuilderRepository)
	if options.TestingEnabled() && normalizedURI == utils.NormalizeGitURI(normalizedSLSAGithubGeneratorRepoURI) {
		return nil
	}

	return utils.IsValidBuilderTag(builderRef, false)
}

// builderID returns the trusted builder ID from the provenance.
// The certTrustedBuilderID input is from the Fulcio certificate.
func builderID(env *dsselib.Envelope, certTrustedBuilderID *utils.TrustedBuilderID) (*utils.TrustedBuilderID, error) {
	prov, err := slsaprovenance.ProvenanceFromEnvelope(certTrustedBuilderID.Name(), env)
	if err != nil {
		return nil, err
	}
	id, err := prov.BuilderID()
	if err != nil {
		return nil, err
	}
	verifiedBuilderID, err := utils.TrustedBuilderIDNew(id, true)
	if err != nil {
		return nil, err
	}
	return verifiedBuilderID, nil
}

// VerifyProvenance verifies the provenance for the given DSSE envelope.
func VerifyProvenance(env *dsselib.Envelope, provenanceOpts *options.ProvenanceOpts, trustedBuilderID *utils.TrustedBuilderID, byob bool,
	expectedID *string) error {
	prov, err := slsaprovenance.ProvenanceFromEnvelope(trustedBuilderID.Name(), env)
	if err != nil {
		return err
	}

	// Verify Builder ID.
	if byob {
		if err := isValidDelegatorBuilderID(prov); err != nil {
			return err
		}

		// If expectedID is not provided, check to see if it is a trusted builder.
		// If not provided, then a trusted builder is expected, to populate provenanceOpts.ExpectedBuilderID
		// with that builder, otherwise, populate from user input.
		//
		// This can verify the actual BYOB builderIDPath against the trusted builderIDPath provided.
		// Currently slsa-framework path is the only one supported for ExpectedBuilderPath.
		if expectedID == nil {
			var trustedBuilderRepositoryPath = httpsGithubCom + trustedBuilderRepository + "/.github/workflows/"
			if provenanceOpts.ExpectedBuilderID, err = verifyBuilderIDPathPrefix(prov, trustedBuilderRepositoryPath); err != nil {
				return err
			}
		} else {
			provenanceOpts.ExpectedBuilderID = *expectedID
		}

		// NOTE: `provenanceOpts.ExpectedBuilderID` is provided by the user
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
