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
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"

	// Load provenance types.
	_ "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/v0.2"
	_ "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/v1.0"
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

func EnvelopeFromBytes(payload []byte) (env *dsselib.Envelope, err error) {
	env = &dsselib.Envelope{}
	err = json.Unmarshal(payload, env)
	return
}

// Verify Builder ID in provenance statement.
// This function does an exact comparison, and expects certBuilderID to be the full
// `name@refs/tags/<name>`.
func verifyBuilderIDExactMatch(prov slsaprovenance.Provenance, certBuilderID string) error {
	builderID, err := prov.BuilderID()
	if err != nil {
		return err
	}
	if certBuilderID != builderID {
		return fmt.Errorf("%w: expected '%s' in builder.id, got '%s'", serrors.ErrorMismatchBuilderID,
			certBuilderID, builderID)
	}

	return nil
}

func asURI(s string) string {
	source := s
	if !strings.HasPrefix(source, "https://") &&
		!strings.HasPrefix(source, "git+") {
		source = "git+https://" + source
	}
	if !strings.HasPrefix(source, "git+") {
		source = "git+" + source
	}

	return source
}

// Verify source URI in provenance statement.
func verifySourceURI(prov slsaprovenance.Provenance, expectedSourceURI string, allowNoMaterialRef bool) error {
	source := asURI(expectedSourceURI)

	// We expect github.com URIs only.
	if !strings.HasPrefix(source, "git+https://github.com/") {
		return fmt.Errorf("%w: expected source github.com repository '%s'", serrors.ErrorMalformedURI,
			source)
	}

	// Verify source from ConfigSource field.
	fullConfigURI, err := prov.ConfigURI()
	if err != nil {
		return err
	}
	configURI, err := sourceFromURI(fullConfigURI, false)
	if err != nil {
		return err
	}
	if configURI != source {
		return fmt.Errorf("%w: expected source '%s' in configSource.uri, got '%s'", serrors.ErrorMismatchSource,
			source, fullConfigURI)
	}

	// Verify source from material section.
	materialSourceURI, err := prov.SourceURI()
	if err != nil {
		return err
	}
	materialURI, err := sourceFromURI(materialSourceURI, allowNoMaterialRef)
	if err != nil {
		return err
	}
	if materialURI != source {
		return fmt.Errorf("%w: expected source '%s' in material section, got '%s'", serrors.ErrorMismatchSource,
			source, materialSourceURI)
	}

	// Last, verify that both fields match.
	// We use the full URI to match on the tag as well.
	if allowNoMaterialRef && len(strings.Split(materialSourceURI, "@")) == 1 {
		// NOTE: this is an exception for npm packages built before GA,
		// see https://github.com/slsa-framework/slsa-verifier/issues/492.
		// We don't need to compare the ref since materialSourceURI does not contain it.
		return nil
	}
	if fullConfigURI != materialSourceURI {
		return fmt.Errorf("%w: material and config URIs do not match: '%s' != '%s'",
			serrors.ErrorInvalidDssePayload,
			fullConfigURI, materialSourceURI)
	}

	return nil
}

// sourceFromURI retrieves the source repository given a repository URI with ref.
//
// NOTE: `allowNoRef` is to allow for verification of npm packages
// generated before GA. Their provenance did not have a ref,
// see https://github.com/slsa-framework/slsa-verifier/issues/492.
// `allowNoRef` should be set to `false` for all other cases.
func sourceFromURI(uri string, allowNoRef bool) (string, error) {
	if uri == "" {
		return "", fmt.Errorf("%w: empty uri", serrors.ErrorMalformedURI)
	}

	r := strings.Split(uri, "@")
	if len(r) < 2 && !allowNoRef {
		return "", fmt.Errorf("%w: %s", serrors.ErrorMalformedURI,
			uri)
	}
	if len(r) < 1 {
		return "", fmt.Errorf("%w: %s", serrors.ErrorMalformedURI,
			uri)
	}
	return r[0], nil
}

// Verify Subject Digest from the provenance statement.
func verifyDigest(prov slsaprovenance.Provenance, expectedHash string) error {
	subjects, err := prov.Subjects()
	if err != nil {
		return err
	}

	// 8 bit represented in hex, so 8/2=4.
	l := len(expectedHash) * 4
	for _, subject := range subjects {
		digestSet := subject.Digest
		hash, exists := digestSet[fmt.Sprintf("sha%v", l)]
		if !exists {
			return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, fmt.Sprintf("no sha%v subject digest", l))
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
	// Collect trusted root material for verification (Rekor pubkeys, SCT pubkeys,
	// Fulcio root certificates).
	_, err := GetTrustedRoot(ctx)
	if err != nil {
		return nil, err
	}

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

func VerifyNpmPackageProvenance(env *dsselib.Envelope, provenanceOpts *options.ProvenanceOpts,
) error {
	prov, err := slsaprovenance.ProvenanceFromEnvelope(env)
	if err != nil {
		return err
	}

	// Untrusted builder.
	if provenanceOpts.ExpectedBuilderID == "" {
		// Verify it's the npm CLI.
		builderID, err := prov.BuilderID()
		if err != nil {
			return err
		}
		// TODO(#494): update the builder ID string.
		if !strings.HasPrefix(builderID, "https://github.com/npm/cli@") {
			return fmt.Errorf("%w: expected 'https://github.com/npm/cli' in builder.id, got '%s'",
				serrors.ErrorMismatchBuilderID, builderID)
		}
	} else if err := verifyBuilderIDExactMatch(prov, provenanceOpts.ExpectedBuilderID); err != nil {
		return err
	}
	// NOTE: for the non trusted builders, the information may be forgeable.
	// Also, the GitHub context is not recorded for the default builder.
	return VerifyProvenanceCommonOptions(prov, provenanceOpts, true)
}

func VerifyProvenance(env *dsselib.Envelope, provenanceOpts *options.ProvenanceOpts,
) error {
	prov, err := slsaprovenance.ProvenanceFromEnvelope(env)
	if err != nil {
		return err
	}

	// Verify Builder ID.
	// Note: `provenanceOpts.ExpectedBuilderID` is not provided by the user,
	// but taken from the certificate. It always is of the form `name@refs/tags/<name>`.
	if err := verifyBuilderIDExactMatch(prov, provenanceOpts.ExpectedBuilderID); err != nil {
		return err
	}

	return VerifyProvenanceCommonOptions(prov, provenanceOpts, false)
}

func VerifyProvenanceCommonOptions(prov slsaprovenance.Provenance, provenanceOpts *options.ProvenanceOpts,
	allowNoMaterialRef bool,
) error {
	// Verify source.
	if err := verifySourceURI(prov, provenanceOpts.ExpectedSourceURI, allowNoMaterialRef); err != nil {
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

func VerifyWorkflowInputs(prov slsaprovenance.Provenance, inputs map[string]string) error {
	pyldInputs, err := prov.GetWorkflowInputs()
	if err != nil {
		return err
	}

	// Verify all inputs.
	for k, v := range inputs {
		value, err := slsaprovenance.GetAsString(pyldInputs, k)
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

func VerifyBranch(prov slsaprovenance.Provenance, expectedBranch string) error {
	branch, err := prov.GetBranch()
	if err != nil {
		return err
	}

	expectedBranch = "refs/heads/" + expectedBranch
	if branch != expectedBranch {
		return fmt.Errorf("expected branch '%s', got '%s': %w", expectedBranch, branch, serrors.ErrorMismatchBranch)
	}

	return nil
}

func VerifyTag(prov slsaprovenance.Provenance, expectedTag string) error {
	tag, err := prov.GetTag()
	if err != nil {
		return err
	}

	expectedTag = "refs/tags/" + expectedTag
	if tag != expectedTag {
		return fmt.Errorf("expected tag '%s', got '%s': %w", expectedTag, tag, serrors.ErrorMismatchTag)
	}

	return nil
}

func VerifyVersionedTag(prov slsaprovenance.Provenance, expectedTag string) error {
	// Retrieve, validate and canonicalize the provenance tag.
	// Note: prerelease is validated as part of patch validation
	// and must be equal. Build is discarded as per https://semver.org/:
	// "Build metadata MUST be ignored when determining version precedence",
	tag, err := prov.GetTag()
	if err != nil {
		return err
	}
	return utils.VerifyVersionedTag(strings.TrimPrefix(tag, "refs/tags/"), expectedTag)
}

// hasCertInEnvelope checks if a valid x509 certificate is present in the
// envelope.
func hasCertInEnvelope(provenance []byte) bool {
	certPem, err := envelope.GetCertFromEnvelope(provenance)
	return err == nil && len(certPem) > 0
}
