package gha

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	sigstoreRoot "github.com/sigstore/sigstore-go/pkg/root"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

type hosted string

const (
	hostedSelf   hosted = "self-hosted"
	hostedGitHub hosted = "github-hosted"

	publishAttestationV01 = "https://github.com/npm/attestation/tree/main/specs/publish/"
)

var intotoStatements = map[string]bool{
	intoto.StatementInTotoV01:         true,
	"https://in-toto.io/Statement/v1": true,
}
var provenancePredicates = map[string]bool{
	common.ProvenanceV02Type: true,
	common.ProvenanceV1Type:  true,
}
var publishPredicates = map[string]bool{
	publishAttestationV01: true,
}
var errrorInvalidAttestations = errors.New("invalid npm attestations")
var attestationKey string
var attestationKeyOnce sync.Once

type attestationSet struct {
	Attestations []attestation `json:"attestations"`
}

type attestation struct {
	PredicateType string      `json:"predicateType"`
	BundleBytes   BundleBytes `json:"bundle"`
}

type BundleBytes []byte

func (b *BundleBytes) UnmarshalJSON(data []byte) error {
	*b = data
	return nil
}

type Npm struct {
	ctx                   context.Context
	root                  *sigstoreRoot.LiveTrustedRoot
	verifiedBuilderID     *utils.TrustedBuilderID
	verifiedProvenanceAtt *SignedAttestation
	verifiedPublishAtt    *SignedAttestation
	provenanceAttestation *attestation
	publishAttestation    *attestation
	clientOpts            *options.ClientOpts
}

func (n *Npm) ProvenanceEnvelope() *dsse.Envelope {
	return n.verifiedProvenanceAtt.Envelope
}

func (n *Npm) ProvenanceLeafCertificate() *x509.Certificate {
	return n.verifiedProvenanceAtt.SigningCert
}

// NpmNew creates a new Npm verifier.
func NpmNew(ctx context.Context, root *sigstoreRoot.LiveTrustedRoot, attestationBytes []byte, clientOpts *options.ClientOpts) (*Npm, error) {
	var aSet attestationSet
	if err := json.Unmarshal(attestationBytes, &aSet); err != nil {
		return nil, fmt.Errorf("%w: json.Unmarshal: %v", errrorInvalidAttestations, err)
	}
	prov, pub, err := extractAttestations(aSet.Attestations)
	if err != nil {
		return nil, err
	}
	return &Npm{
		ctx:  ctx,
		root: root,

		provenanceAttestation: prov,
		publishAttestation:    pub,
		clientOpts:            clientOpts,
	}, nil
}

func extractAttestations(attestations []attestation) (*attestation, *attestation, error) {
	if len(attestations) < 2 {
		return nil, nil, fmt.Errorf("%w: invalid number of attestations: %v", errrorInvalidAttestations, len(attestations))
	}

	var provenanceAttestation *attestation
	var publishAttestation *attestation
	for i := range attestations {
		att := attestations[i]
		// Provenance type verification.
		if _, ok := provenancePredicates[att.PredicateType]; ok {
			provenanceAttestation = &att
		}
		// Publish type verification.
		if strings.HasPrefix(att.PredicateType, publishAttestationV01) {
			publishAttestation = &att
		}
	}

	if provenanceAttestation == nil || publishAttestation == nil {
		return nil, nil, fmt.Errorf("%w: invalid attestation types", errrorInvalidAttestations)
	}
	return provenanceAttestation, publishAttestation, nil
}

// getAttestationKey retrieves the attestation key and holds it in memory.
func getAttestationKey(sigstoreTUFClient utils.SigstoreTUFClient, npmRegistryPublicKeyID string) (string, error) {
	var err error
	attestationKeyOnce.Do(func() {
		attestationKey, err = getKeyDataFromSigstoreTUF(sigstoreTUFClient, npmRegistryPublicKeyID, attestationKeyUsage)
	})
	if err != nil {
		return "", err
	}
	return attestationKey, nil
}

func (n *Npm) verifyProvenanceAttestationSignature() error {
	// Re-use the standard bundle verification.
	signedProvenance, err := VerifyProvenanceBundle(n.ctx, n.provenanceAttestation.BundleBytes, n.root)
	if err != nil {
		return err
	}
	n.verifiedProvenanceAtt = signedProvenance
	return nil
}

func (n *Npm) verifyPublishAttestationSignature() error {
	// First verify the bundle and its rekor entry.
	signedPublish, err := verifyBundleAndEntryFromBytes(n.ctx, n.publishAttestation.BundleBytes, n.root, false)
	if err != nil {
		return err
	}

	// Get the keyID used to sign the attestaion.
	// It is untrusted until we search the TUF root and find and key with the same KeyID.
	npmRegistryPublicKeyID := signedPublish.PublicKey.Hint

	// Retrieve the key material.
	// We found the associated public key in the TUF root, so now we can trust this KeyID.
	npmRegistryPublicKey, err := getAttestationKey(n.clientOpts.SigstoreTUFClient, npmRegistryPublicKeyID)
	if err != nil {
		return err
	}

	// Verify the PAE signature.
	derKey, err := base64.StdEncoding.DecodeString(npmRegistryPublicKey)
	if err != nil {
		return fmt.Errorf("DecodeString: %w", err)
	}

	envVerifier, err := utils.DsseVerifierNew(derKey, utils.KeyFormatDER, npmRegistryPublicKeyID, nil)
	if err != nil {
		return err
	}

	_, err = envVerifier.Verify(context.Background(), signedPublish.Envelope)
	if err != nil {
		return fmt.Errorf("%w: %w", serrors.ErrorInvalidSignature, err)
	}

	// Verification done.
	n.verifiedPublishAtt = signedPublish
	return nil
}

func (n *Npm) verifyIntotoHeaders() error {
	if err := verifyIntotoTypes(n.verifiedProvenanceAtt, provenancePredicates, intoto.PayloadType, false); err != nil {
		return err
	}
	if err := verifyIntotoTypes(n.verifiedPublishAtt, publishPredicates, intoto.PayloadType, true); err != nil {
		return err
	}
	return nil
}

func verifyIntotoTypes(att *SignedAttestation, predicateTypes map[string]bool, payloadType string, prefix bool) error {
	env := att.Envelope
	pyld, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}

	var statement intoto.Statement
	if err := json.Unmarshal(pyld, &statement); err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}

	// Envelope verification.
	if env.PayloadType != payloadType {
		return fmt.Errorf("%w: expected payload type '%v', got '%s'",
			serrors.ErrorInvalidDssePayload, payloadType, env.PayloadType)
	}

	// Statement verification.
	if _, exists := intotoStatements[statement.Type]; !exists {
		return fmt.Errorf("%w: expected statement header type one of '%v', got '%s'",
			serrors.ErrorInvalidDssePayload, intotoStatements, statement.Type)
	}

	if !prefix {
		if _, exists := predicateTypes[statement.PredicateType]; !exists {
			return fmt.Errorf("%w: expected predicate type one of '%v', got '%s'", serrors.ErrorInvalidDssePayload, predicateTypes, statement.PredicateType)
		}
	}

	if prefix {
		hasPrefix := false
		for k := range predicateTypes {
			if strings.HasPrefix(statement.PredicateType, k) {
				hasPrefix = true
				break
			}
		}
		if !hasPrefix {
			return fmt.Errorf("%w: expected predicate type with prefix one of '%v', got '%s'",
				serrors.ErrorInvalidDssePayload, predicateTypes, statement.PredicateType)
		}
	}
	return nil
}

func (n *Npm) verifyPackageName(name *string) error {
	if name == nil {
		return nil
	}

	// Verify subject name in provenance.
	if err := verifyProvenanceSubjectName(n.verifiedBuilderID, n.verifiedProvenanceAtt, *name); err != nil {
		return err
	}

	// Verify subject name in publish attestation.
	if err := verifyPublishSubjectName(n.verifiedPublishAtt, *name); err != nil {
		return err
	}

	// Verify predicate name in publish attestation.
	if err := verifyPublishPredicateName(n.verifiedPublishAtt, *name); err != nil {
		return err
	}

	return nil
}

func (n *Npm) verifyPackageVersion(version *string) error {
	if version == nil {
		return nil
	}

	// Verify subject version in provenance.
	if err := verifyProvenanceSubjectVersion(n.verifiedBuilderID, n.verifiedProvenanceAtt, *version); err != nil {
		return err
	}

	// Verify subject version in publish attestation.
	if err := verifyPublishSubjectVersion(n.verifiedPublishAtt, *version); err != nil {
		return err
	}

	// Verify predicate version in publish attestation.
	if err := verifyPublishPredicateVersion(n.verifiedPublishAtt, *version); err != nil {
		return err
	}

	return nil
}

func (n *Npm) verifyBuilderID(
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
	defaultBuilders map[string]bool,
) (*utils.TrustedBuilderID, error) {
	// Verify certificate information.
	builder, err := verifyNpmEnvAndCert(
		n.ProvenanceEnvelope(),
		n.ProvenanceLeafCertificate(),
		provenanceOpts, builderOpts,
		defaultBuilders,
	)
	if err != nil {
		return nil, err
	}
	n.verifiedBuilderID = builder
	return builder, err
}

func verifyPublishPredicateVersion(att *SignedAttestation, expectedVersion string) error {
	_, version, err := publishPredicateData(att)
	if err != nil {
		return err
	}
	if version != expectedVersion {
		return fmt.Errorf("%w: got '%v', expected '%v'", serrors.ErrorMismatchPackageVersion,
			version, expectedVersion)
	}
	return nil
}

func verifyPublishPredicateName(att *SignedAttestation, expectedName string) error {
	name, _, err := publishPredicateData(att)
	if err != nil {
		return err
	}
	if name != expectedName {
		return fmt.Errorf("%w: got '%v', expected '%v'", serrors.ErrorMismatchPackageName,
			name, expectedName)
	}
	return nil
}

func subjectsFromAttestation(att *SignedAttestation) ([]intoto.Subject, error) {
	env := att.Envelope
	pyld, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", serrors.ErrorInvalidDssePayload, err)
	}
	statement := struct {
		intoto.StatementHeader
	}{}
	if err := json.Unmarshal(pyld, &statement); err != nil {
		return nil, fmt.Errorf("%w: %w", serrors.ErrorInvalidDssePayload, err)
	}

	if len(statement.Subject) == 0 {
		return nil, fmt.Errorf("%w: no subjects", serrors.ErrorInvalidDssePayload)
	}
	return statement.Subject, nil
}

func publishPredicateData(att *SignedAttestation) (string, string, error) {
	env := att.Envelope
	pyld, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}

	statement := struct {
		intoto.StatementHeader
		Predicate struct {
			Version string `json:"version"`
			Name    string `json:"name"`
		} `json:"predicate"`
	}{}
	if err := json.Unmarshal(pyld, &statement); err != nil {
		return "", "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}

	return statement.Predicate.Name, statement.Predicate.Version, nil
}

func verifyProvenanceSubjectVersion(b *utils.TrustedBuilderID, att *SignedAttestation, expectedVersion string) error {
	subject, err := getSubject(b, att)
	if err != nil {
		return err
	}

	_, subVersion, err := getPackageNameAndVersion(subject)
	if err != nil {
		return err
	}

	if subVersion != expectedVersion {
		return fmt.Errorf("%w: got '%v', expected '%v'", serrors.ErrorMismatchPackageVersion,
			subVersion, expectedVersion)
	}

	return nil
}

func (n *Npm) verifyPublishAttestationSubjectDigest(expectedHash string) error {
	publishSubjects, err := subjectsFromAttestation(n.verifiedPublishAtt)
	if err != nil {
		return err
	}

	// 8 bit represented in hex, so 8/2=4.
	bitLength := len(expectedHash) * 4
	expectedAlgo := fmt.Sprintf("sha%v", bitLength)
	if bitLength < 256 {
		return fmt.Errorf("%w: expected minimum sha256, got %s", serrors.ErrorInvalidHash, expectedAlgo)
	}

	for _, subject := range publishSubjects {
		digestSet := subject.Digest
		hash, exists := digestSet[expectedAlgo]
		if !exists {
			continue
		}
		if hash == expectedHash {
			return nil
		}
	}

	// NOTE: We don't need to verify that the digest matches the one in the provenance
	// because the provenance verification will verify the hash as well.
	return fmt.Errorf("expected hash '%s' not found: %w", expectedHash, serrors.ErrorMismatchHash)
}

func verifyPublishSubjectVersion(att *SignedAttestation, expectedVersion string) error {
	_, version, err := publishPredicateData(att)
	if err != nil {
		return err
	}

	if version != expectedVersion {
		return fmt.Errorf("%w: got '%v', expected '%v'", serrors.ErrorMismatchPackageVersion,
			version, expectedVersion)
	}

	return nil
}

func verifyPublishSubjectName(att *SignedAttestation, expectedName string) error {
	name, _, err := publishPredicateData(att)
	if err != nil {
		return err
	}

	return verifyName(name, expectedName)
}

func verifyProvenanceSubjectName(b *utils.TrustedBuilderID, att *SignedAttestation, expectedName string) error {
	prov, err := slsaprovenance.ProvenanceFromEnvelope(b.Name(), att.Envelope)
	if err != nil {
		return fmt.Errorf("reading provenance: %w", err)
	}

	subjects, err := prov.Subjects()
	if err != nil {
		return fmt.Errorf("%w: %w", serrors.ErrorInvalidDssePayload, err)
	}
	if len(subjects) != 1 {
		return fmt.Errorf("%w: expected 1 subject, got %v", serrors.ErrorInvalidDssePayload, len(subjects))
	}

	// Package name starts with a prefix.
	prefix := "pkg:npm/"
	if !strings.HasPrefix(subjects[0].Name, prefix) {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidPackageName, subjects[0].Name)
	}

	// URL decode the package name from the attestation.
	subjectName, err := url.QueryUnescape(subjects[0].Name[len(prefix):])
	if err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidEncoding, err)
	}

	return verifyName(subjectName, expectedName)
}

func verifyName(actual, expected string) error {
	subName, _, err := getPackageNameAndVersion(actual)
	if err != nil {
		return err
	}

	if subName != expected {
		return fmt.Errorf("%w: got '%v', expected '%v'", serrors.ErrorMismatchPackageName,
			subName, expected)
	}

	return nil
}

func getPackageNameAndVersion(name string) (string, string, error) {
	var pkgname, pkgtag string
	n := name
	if strings.HasPrefix(name, "@") {
		n = n[1:]
	}
	parts := strings.Split(n, "@")
	if len(parts) > 2 {
		return "", "", fmt.Errorf("%w: %v", serrors.ErrorInvalidPackageName, name)
	}

	pkgname = parts[0]
	if strings.HasPrefix(name, "@") {
		pkgname = "@" + pkgname
	}
	if len(parts) == 2 {
		pkgtag = parts[1]
	}

	return pkgname, pkgtag, nil
}

func getSubject(b *utils.TrustedBuilderID, att *SignedAttestation) (string, error) {
	prov, err := slsaprovenance.ProvenanceFromEnvelope(b.Name(), att.Envelope)
	if err != nil {
		return "", err
	}

	subjects, err := prov.Subjects()
	if err != nil {
		return "", fmt.Errorf("%w", err)
	}
	if len(subjects) != 1 {
		return "", fmt.Errorf("%w: subject length: %v", serrors.ErrorInvalidSubject, len(subjects))
	}

	// Package name starts with a prefix.
	prefix := "pkg:npm/"
	if !strings.HasPrefix(subjects[0].Name, prefix) {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidPackageName, subjects[0].Name)
	}

	// URL decode the package name from the attestation.
	subject, err := url.QueryUnescape(subjects[0].Name[len(prefix):])
	if err != nil {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidEncoding, err)
	}
	return subject, err
}
