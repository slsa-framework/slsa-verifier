package gha

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/semver"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/client"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/slsa-framework/slsa-verifier/options"
)

func EnvelopeFromBytes(payload []byte) (env *dsselib.Envelope, err error) {
	env = &dsselib.Envelope{}
	err = json.Unmarshal(payload, env)
	return
}

func provenanceFromEnv(env *dsselib.Envelope) (prov *intoto.ProvenanceStatement, err error) {
	pyld, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "decoding payload")
	}
	prov = &intoto.ProvenanceStatement{}
	if err := json.Unmarshal(pyld, prov); err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "unmarshalling json")
	}
	return
}

// Verify Builder ID in provenance statement.
func verifyBuilderID(prov *intoto.ProvenanceStatement, builderID string) error {
	// Check that the BuilderID is well-formed.
	provid, err := sourceFromURI(prov.Predicate.Builder.ID, false)
	if err != nil {
		return err
	}
	// Note: builderID does not contain the tag.
	// TODO(#189): support cases where user wants to match on the full builderID, including the tag.
	bid, err := sourceFromURI(builderID, true)
	if err != nil {
		return err
	}
	if provid != bid {
		return fmt.Errorf("%w: expected '%s' in builder.id, got '%s'", serrors.ErrorMismatchBuilderID,
			bid, provid)
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
func verifySourceURI(prov *intoto.ProvenanceStatement, expectedSourceURI string) error {
	source := asURI(expectedSourceURI)

	// We expect github.com URIs only.
	if !strings.HasPrefix(source, "git+https://github.com/") {
		return fmt.Errorf("%w: expected source github.com repository '%s'", serrors.ErrorMalformedURI,
			source)
	}

	// Verify source from ConfigSource field.
	configURI, err := sourceFromURI(prov.Predicate.Invocation.ConfigSource.URI, false)
	if err != nil {
		return err
	}
	if configURI != source {
		return fmt.Errorf("%w: expected source '%s' in configSource.uri, got '%s'", serrors.ErrorMismatchSource,
			source, prov.Predicate.Invocation.ConfigSource.URI)
	}

	// Verify source from material section.
	if len(prov.Predicate.Materials) == 0 {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no material")
	}
	materialURI, err := sourceFromURI(prov.Predicate.Materials[0].URI, false)
	if err != nil {
		return err
	}
	if materialURI != source {
		return fmt.Errorf("%w: expected source '%s' in material section, got '%s'", serrors.ErrorMismatchSource,
			source, prov.Predicate.Materials[0].URI)
	}

	// Last, verify that both fields match.
	// We use the full URI to match on the tag as well.
	if prov.Predicate.Invocation.ConfigSource.URI != prov.Predicate.Materials[0].URI {
		return fmt.Errorf("%w: material and config URIs do not match: '%s' != '%s'",
			serrors.ErrorInvalidDssePayload,
			prov.Predicate.Invocation.ConfigSource.URI, prov.Predicate.Materials[0].URI)
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
func verifySha256Digest(prov *intoto.ProvenanceStatement, expectedHash string) error {
	if len(prov.Subject) == 0 {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}

	for _, subject := range prov.Subject {
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
func VerifyProvenanceSignature(ctx context.Context, rClient *client.Rekor, provenance []byte, artifactHash string) (*dsselib.Envelope, *x509.Certificate, error) {
	// Get Rekor entries corresponding to provenance
	env, cert, err := GetRekorEntriesWithCert(rClient, provenance)
	if err == nil {
		return env, cert, nil
	}

	// Fallback on using the redis search index to get matching UUIDs.
	fmt.Fprintf(os.Stderr, "Getting rekor entry error %s, trying Redis search index to find entries by subject digest\n", err)
	uuids, err := GetRekorEntries(rClient, artifactHash)
	if err != nil {
		return nil, nil, err
	}

	env, err = EnvelopeFromBytes(provenance)
	if err != nil {
		return nil, nil, err
	}

	// Verify the provenance and return the signing certificate.
	cert, err = FindSigningCertificate(ctx, uuids, *env, rClient)
	if err != nil {
		return nil, nil, err
	}

	return env, cert, nil
}

func VerifyProvenance(env *dsselib.Envelope, provenanceOpts *options.ProvenanceOpts) error {
	prov, err := provenanceFromEnv(env)
	if err != nil {
		return err
	}

	// Verify Builder ID.
	if err := verifyBuilderID(prov, provenanceOpts.ExpectedBuilderID); err != nil {
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

	return nil
}

func VerifyBranch(prov *intoto.ProvenanceStatement, expectedBranch string) error {
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

func VerifyTag(prov *intoto.ProvenanceStatement, expectedTag string) error {
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

func VerifyVersionedTag(prov *intoto.ProvenanceStatement, expectedTag string) error {
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

func getAsString(environment map[string]interface{}, field string) (string, error) {
	value, ok := environment[field]
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

func getAsAny(environment map[string]any, field string) (any, error) {
	value, ok := environment[field]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("environment type for %s", field))
	}
	return value, nil
}

func getEventPayload(environment map[string]interface{}) (map[string]interface{}, error) {
	eventPayload, ok := environment["github_event_payload"]
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type event payload")
	}

	payload, ok := eventPayload.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type payload")
	}

	return payload, nil
}

func getBaseRef(environment map[string]interface{}) (string, error) {
	baseRef, err := getAsString(environment, "github_base_ref")
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
	eventName, err := getAsString(environment, "github_event_name")
	if err != nil {
		return "", err
	}

	if eventName != "push" {
		return "", nil
	}

	payload, err := getEventPayload(environment)
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

func getTargetCommittish(environment map[string]interface{}) (string, error) {
	eventName, err := getAsString(environment, "github_event_name")
	if err != nil {
		return "", err
	}

	if eventName != "release" {
		return "", nil
	}

	payload, err := getEventPayload(environment)
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

func getBranchForTag(environment map[string]interface{}) (string, error) {
	// First try the base_ref.
	branch, err := getBaseRef(environment)
	if branch != "" || err != nil {
		return branch, err
	}

	// Second try the target comittish.
	return getTargetCommittish(environment)
}

// Get tag from the provenance invocation parameters.
func getTag(prov *intoto.ProvenanceStatement) (string, error) {
	environment, ok := prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	refType, err := getAsString(environment, "github_ref_type")
	if err != nil {
		return "", err
	}

	switch refType {
	case "branch":
		return "", nil
	case "tag":
		return getAsString(environment, "github_ref")
	default:
		return "", fmt.Errorf("%w: %s %s", serrors.ErrorInvalidDssePayload,
			"unknown ref type", refType)
	}
}

// Get branch from the provenance invocation parameters.
func getBranch(prov *intoto.ProvenanceStatement) (string, error) {
	environment, ok := prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	refType, err := getAsString(environment, "github_ref_type")
	if err != nil {
		return "", err
	}

	switch refType {
	case "branch":
		return getAsString(environment, "github_ref")
	case "tag":
		return getBranchForTag(environment)
	default:
		return "", fmt.Errorf("%w: %s %s", serrors.ErrorInvalidDssePayload,
			"unknown ref type", refType)
	}
}
