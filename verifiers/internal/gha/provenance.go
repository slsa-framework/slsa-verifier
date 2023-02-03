package gha

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/semver"

	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"

	"github.com/slsa-framework/slsa-github-generator/signing/envelope"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"
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
	if certBuilderID != prov.BuilderID() {
		return fmt.Errorf("%w: expected '%s' in builder.id, got '%s'", serrors.ErrorMismatchBuilderID,
			certBuilderID, prov.BuilderID())
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
func verifySourceURI(prov slsaprovenance.Provenance, expectedSourceURI string) error {
	source := asURI(expectedSourceURI)

	// We expect github.com URIs only.
	if !strings.HasPrefix(source, "git+https://github.com/") {
		return fmt.Errorf("%w: expected source github.com repository '%s'", serrors.ErrorMalformedURI,
			source)
	}

	// Verify source from ConfigSource field.
	configURI, err := sourceFromURI(prov.ConfigURI(), false)
	if err != nil {
		return err
	}
	if configURI != source {
		return fmt.Errorf("%w: expected source '%s' in configSource.uri, got '%s'", serrors.ErrorMismatchSource,
			source, prov.ConfigURI())
	}

	// Verify source from material section.
	materialSourceURI, err := prov.SourceURI()
	if err != nil {
		return err
	}
	materialURI, err := sourceFromURI(materialSourceURI, false)
	if err != nil {
		return err
	}
	if materialURI != source {
		return fmt.Errorf("%w: expected source '%s' in material section, got '%s'", serrors.ErrorMismatchSource,
			source, materialSourceURI)
	}

	// Last, verify that both fields match.
	// We use the full URI to match on the tag as well.
	if prov.ConfigURI() != materialSourceURI {
		return fmt.Errorf("%w: material and config URIs do not match: '%s' != '%s'",
			serrors.ErrorInvalidDssePayload,
			prov.ConfigURI(), materialSourceURI)
	}

	return nil
}

func sourceFromURI(uri string, allowNotTag bool) (string, error) {
	if uri == "" {
		return "", fmt.Errorf("%w: empty uri", serrors.ErrorMalformedURI)
	}

	r := strings.SplitN(uri, "@", 2)
	if len(r) < 2 && !allowNotTag {
		return "", fmt.Errorf("%w: %s", serrors.ErrorMalformedURI,
			uri)
	}
	if len(r) < 1 {
		return "", fmt.Errorf("%w: %s", serrors.ErrorMalformedURI,
			uri)
	}
	return r[0], nil
}

// Verify SHA256 Subject Digest from the provenance statement.
func verifySha256Digest(prov slsaprovenance.Provenance, expectedHash string) error {
	if len(prov.Subjects()) == 0 {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}

	for _, subject := range prov.Subjects() {
		digestSet := subject.Digest
		hash, exists := digestSet["sha256"]
		if !exists {
			return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no sha256 subject digest")
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
	*SignedAttestation, error) {
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

func VerifyProvenance(env *dsselib.Envelope, provenanceOpts *options.ProvenanceOpts) error {
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

	// Verify source.
	if err := verifySourceURI(prov, provenanceOpts.ExpectedSourceURI); err != nil {
		return err
	}

	// Verify subject digest.
	if err := verifySha256Digest(prov, provenanceOpts.ExpectedDigest); err != nil {
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
	// Verify it's a workflow_dispatch trigger.
	triggerName, err := prov.GetStringFromEnvironment("github_event_name")
	if err != nil {
		return err
	}
	if triggerName != "workflow_dispatch" {
		return fmt.Errorf("%w: expected 'workflow_dispatch' trigger, got %s",
			serrors.ErrorMismatchWorkflowInputs, triggerName)
	}

	// Assume no nested level.
	pyldInputs, err := prov.GetInputs()
	if err != nil {
		return err
	}

	// Verify all inputs.
	for k, v := range inputs {
		value, err := getAsString(pyldInputs, k)
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
	branch, err := getBranch(prov)
	if err != nil {
		return err
	}

	expectedBranch = "refs/heads/" + expectedBranch
	if !strings.EqualFold(branch, expectedBranch) {
		return fmt.Errorf("expected branch '%s', got '%s': %w", expectedBranch, branch, serrors.ErrorMismatchBranch)
	}

	return nil
}

func VerifyTag(prov slsaprovenance.Provenance, expectedTag string) error {
	tag, err := getTag(prov)
	if err != nil {
		return err
	}

	expectedTag = "refs/tags/" + expectedTag
	if !strings.EqualFold(tag, expectedTag) {
		return fmt.Errorf("expected tag '%s', got '%s': %w", expectedTag, tag, serrors.ErrorMismatchTag)
	}

	return nil
}

func VerifyVersionedTag(prov slsaprovenance.Provenance, expectedTag string) error {
	// Validate and canonicalize the provenance tag.
	if !semver.IsValid(expectedTag) {
		return fmt.Errorf("%s: %w", expectedTag, serrors.ErrorInvalidSemver)
	}

	// Retrieve, validate and canonicalize the provenance tag.
	// Note: prerelease is validated as part of patch validation
	// and must be equal. Build is discarded as per https://semver.org/:
	// "Build metadata MUST be ignored when determining version precedence",
	tag, err := getTag(prov)
	if err != nil {
		return err
	}
	semTag := semver.Canonical(strings.TrimPrefix(tag, "refs/tags/"))
	if !semver.IsValid(semTag) {
		return fmt.Errorf("%s: %w", expectedTag, serrors.ErrorInvalidSemver)
	}

	// Major should always be the same.
	expectedMajor := semver.Major(expectedTag)
	major := semver.Major(semTag)
	if major != expectedMajor {
		return fmt.Errorf("%w: major version expected '%s', got '%s'",
			serrors.ErrorMismatchVersionedTag, expectedMajor, major)
	}

	expectedMinor, err := minorVersion(expectedTag)
	if err == nil {
		// A minor version was provided by the user.
		minor, err := minorVersion(semTag)
		if err != nil {
			return err
		}

		if minor != expectedMinor {
			return fmt.Errorf("%w: minor version expected '%s', got '%s'",
				serrors.ErrorMismatchVersionedTag, expectedMinor, minor)
		}
	}

	expectedPatch, err := patchVersion(expectedTag)
	if err == nil {
		// A patch version was provided by the user.
		patch, err := patchVersion(semTag)
		if err != nil {
			return err
		}

		if patch != expectedPatch {
			return fmt.Errorf("%w: patch version expected '%s', got '%s'",
				serrors.ErrorMismatchVersionedTag, expectedPatch, patch)
		}
	}

	// Match.
	return nil
}

func minorVersion(v string) (string, error) {
	return extractFromVersion(v, 1)
}

func patchVersion(v string) (string, error) {
	patch, err := extractFromVersion(v, 2)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(patch, semver.Build(v)), nil
}

func extractFromVersion(v string, i int) (string, error) {
	parts := strings.Split(v, ".")
	if len(parts) <= i {
		return "", fmt.Errorf("%s: %w", v, serrors.ErrorInvalidSemver)
	}
	return parts[i], nil
}

func getAsAny(payload map[string]any, field string) (any, error) {
	value, ok := payload[field]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("payload type for %s", field))
	}
	return value, nil
}

func getAsString(pyld map[string]interface{}, field string) (string, error) {
	value, ok := pyld[field]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("environment type for %s", field))
	}

	i, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s '%s'", serrors.ErrorInvalidDssePayload, "environment type string", field)
	}
	return i, nil
}

func getEventPayload(prov slsaprovenance.Provenance) (map[string]interface{}, error) {
	eventPayload, err := prov.GetAnyFromEnvironment("github_event_payload")
	if err != nil {
		return nil, err
	}

	payload, ok := eventPayload.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type payload")
	}

	return payload, nil
}

func getBaseRef(prov slsaprovenance.Provenance) (string, error) {
	baseRef, err := prov.GetStringFromEnvironment("github_base_ref")
	if err != nil {
		return "", err
	}

	// This `base_ref` seems to always be "".
	if baseRef != "" {
		return baseRef, nil
	}

	// Look at the event payload instead.
	// We don't do that for all triggers because the payload
	// is event-specific; and only the `push` event seems to have a `base_ref`.
	eventName, err := prov.GetStringFromEnvironment("github_event_name")
	if err != nil {
		return "", err
	}

	if eventName != "push" {
		return "", nil
	}

	payload, err := getEventPayload(prov)
	if err != nil {
		return "", err
	}

	value, err := getAsAny(payload, "base_ref")
	if err != nil {
		return "", err
	}

	// The `base_ref` field may be nil if the build was from
	// a specific commit rather than a branch.
	v, ok := value.(string)
	if !ok {
		return "", nil
	}
	return v, nil
}

func getTargetCommittish(prov slsaprovenance.Provenance) (string, error) {
	eventName, err := prov.GetStringFromEnvironment("github_event_name")
	if err != nil {
		return "", err
	}

	if eventName != "release" {
		return "", nil
	}

	payload, err := getEventPayload(prov)
	if err != nil {
		return "", err
	}

	// For a release event, we look for release.target_commitish.
	releasePayload, ok := payload["release"]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "release absent from payload")
	}

	release, ok := releasePayload.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type releasePayload")
	}

	branch, err := getAsString(release, "target_commitish")
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, "target_commitish not present")
	}

	return "refs/heads/" + branch, nil
}

func getBranchForTag(prov slsaprovenance.Provenance) (string, error) {
	// First try the base_ref.
	branch, err := getBaseRef(prov)
	if branch != "" || err != nil {
		return branch, err
	}

	// Second try the target comittish.
	return getTargetCommittish(prov)
}

// Get tag from the provenance invocation parameters.
func getTag(prov slsaprovenance.Provenance) (string, error) {
	refType, err := prov.GetStringFromEnvironment("github_ref_type")
	if err != nil {
		return "", err
	}

	switch refType {
	case "branch":
		return "", nil
	case "tag":
		return prov.GetStringFromEnvironment("github_ref")
	default:
		return "", fmt.Errorf("%w: %s %s", serrors.ErrorInvalidDssePayload,
			"unknown ref type", refType)
	}
}

// Get branch from the provenance invocation parameters.
func getBranch(prov slsaprovenance.Provenance) (string, error) {
	refType, err := prov.GetStringFromEnvironment("github_ref_type")
	if err != nil {
		return "", err
	}

	switch refType {
	case "branch":
		return prov.GetStringFromEnvironment("github_ref")
	case "tag":
		return getBranchForTag(prov)
	default:
		return "", fmt.Errorf("%w: %s %s", serrors.ErrorInvalidDssePayload,
			"unknown ref type", refType)
	}
}

// hasCertInEnvelope checks if a valid x509 certificate is present in the
// envelope.
func hasCertInEnvelope(provenance []byte) bool {
	certPem, err := envelope.GetCertFromEnvelope(provenance)
	return err == nil && len(certPem) > 0
}
