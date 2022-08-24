package gcb

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa01 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/slsa-framework/slsa-verifier/options"
	"github.com/slsa-framework/slsa-verifier/verifiers/internal/gcb/keys"
)

var GCBBuilderIDs = []string{"https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2"}

type v01IntotoStatement struct {
	intoto.StatementHeader
	Predicate slsa01.ProvenancePredicate `json:"predicate"`
}

type provenance struct {
	Build struct {
		// TODO: compare to verified provenance.
		// IntotoStatement v01IntotoStatement `json:"intotoStatement"`
	} `json:"build"`
	Kind        string           `json:"kind"`
	ResourceURI string           `json:"resourceUri"`
	Envelope    dsselib.Envelope `json:"envelope"`
}

type gloudProvenance struct {
	ImageSummary struct {
		Digest               string `json:"digest"`
		FullyQualifiedDigest string `json:"fully_qualified_digest"`
		Registry             string `json:"registry"`
		Repsitory            string `json:"repository"`
	} `json:"image_summary"`
	ProvenanceSummary struct {
		Provenance []provenance `json:"provenance"`
	} `json:"provenance_summary"`
}

type Provenance struct {
	gcloudProv              *gloudProvenance
	verifiedProvenance      *provenance
	verifiedIntotoStatement *v01IntotoStatement
}

func ProvenanceFromBytes(payload []byte) (*Provenance, error) {
	var prov gloudProvenance
	err := json.Unmarshal(payload, &prov)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal: %w", err)
	}

	return &Provenance{
		gcloudProv: &prov,
	}, nil
}

func payloadFromEnvelope(env *dsselib.Envelope) ([]byte, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	return payload, nil
}

func (self *Provenance) isVerified() error {
	// Check that the signature is verified.
	if self.verifiedIntotoStatement == nil ||
		self.verifiedProvenance == nil {
		return serrors.ErrorNoValidSignature
	}
	return nil
}

func (self *Provenance) GetVerifiedIntotoStatement() ([]byte, error) {
	if err := self.isVerified(); err != nil {
		return nil, err
	}
	d, err := json.Marshal(self.verifiedIntotoStatement)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	return d, nil
}

// VerifyMetadata verifies additional metadata contained in the provenance, which is not part
// of the DSSE payload or headers. It is part of the payload returned by
// `gcloud artifacts docker images describe image:tag --format json --show-provenance`.
func (self *Provenance) VerifyMetadata(provenanceOpts *options.ProvenanceOpts) error {
	if err := self.isVerified(); err != nil {
		return err
	}

	if provenanceOpts == nil {
		return nil
	}
	prov := self.verifiedProvenance

	if prov.Kind != "BUILD" {
		return fmt.Errorf("%w: expected kind to be 'BUILD', got %s", serrors.ErrorInvalidFormat, prov.Kind)
	}

	// Note: this could be verified in `VerifySourceURI`, but it is kept here
	// because it is not part of the DSSE intoto payload.
	// The `ResourceURI` is container@sha256:hash, without the tag.
	// We only verify the URI's sha256 for simplicity.
	if !strings.HasSuffix(prov.ResourceURI, "@sha256:"+provenanceOpts.ExpectedDigest) {
		return fmt.Errorf("%w: expected resourceUri '%s', got '%s'",
			serrors.ErrorMismatchHash, provenanceOpts.ExpectedDigest, prov.ResourceURI)
	}
	return nil
}

// VerifySummary verifies the content of the `image_summary` structure
// returned by `gcloud artifacts docker images describe image:tag --format json --show-provenance`.
func (self *Provenance) VerifySummary(provenanceOpts *options.ProvenanceOpts) error {
	if err := self.isVerified(); err != nil {
		return err
	}

	if provenanceOpts == nil {
		return nil
	}

	// Validate the digest.
	if self.gcloudProv.ImageSummary.Digest != "sha256:"+provenanceOpts.ExpectedDigest {
		return fmt.Errorf("%w: expected summary digest '%s', got '%s'",
			serrors.ErrorMismatchHash, provenanceOpts.ExpectedDigest,
			self.gcloudProv.ImageSummary.Digest)
	}

	// Validate the qualified digest.
	if !strings.HasSuffix(self.gcloudProv.ImageSummary.FullyQualifiedDigest,
		"sha256:"+provenanceOpts.ExpectedDigest) {
		return fmt.Errorf("%w: expected fully qualifiedd digest '%s', got '%s'",
			serrors.ErrorMismatchHash, provenanceOpts.ExpectedDigest,
			self.gcloudProv.ImageSummary.FullyQualifiedDigest)
	}
	return nil
}

// VerifyIntotoHeaders verifies the headers are intoto format and the expected
// slsa predicate.
func (self *Provenance) VerifyIntotoHeaders() error {
	if err := self.isVerified(); err != nil {
		return err
	}

	statement := self.verifiedIntotoStatement
	// https://in-toto.io/Statement/v0.1
	if statement.StatementHeader.Type != intoto.StatementInTotoV01 {
		return fmt.Errorf("%w: expected statement header type '%s', got '%s'",
			serrors.ErrorInvalidDssePayload, intoto.StatementInTotoV01, statement.StatementHeader.Type)
	}

	// https://slsa.dev/provenance/v0.1
	if statement.StatementHeader.PredicateType != slsa01.PredicateSLSAProvenance {
		return fmt.Errorf("%w: expected statement predicate type '%s', got '%s'",
			serrors.ErrorInvalidDssePayload, slsa01.PredicateSLSAProvenance, statement.StatementHeader.PredicateType)
	}

	return nil
}

func isValidBuilderID(id string) error {
	for _, b := range GCBBuilderIDs {
		if id == b {
			return nil
		}
	}
	return serrors.ErrorMismatchBuilderID
}

// VerifyBuilder verifies the builder in the DSSE payload:
// - in the recipe type
// - the recipe argument type
// - the predicate builder ID
func (self *Provenance) VerifyBuilder(builderOpts *options.BuilderOpts) (string, error) {
	if err := self.isVerified(); err != nil {
		return "", err
	}

	statement := self.verifiedIntotoStatement
	predicateBuilderID := statement.Predicate.Builder.ID

	// Sanity check the builderID.
	if err := isValidBuilderID(predicateBuilderID); err != nil {
		return "", err
	}

	// Validate with user-provided value.
	if builderOpts != nil && builderOpts.ExpectedID != nil {
		if *builderOpts.ExpectedID != predicateBuilderID {
			return "", fmt.Errorf("%w: expected '%s', got '%s'", serrors.ErrorMismatchBuilderID,
				*builderOpts.ExpectedID, predicateBuilderID)
		}
	}

	// Valiate that the recipe type is consistent.
	if predicateBuilderID != statement.Predicate.Recipe.Type {
		return "", fmt.Errorf("%w: expected '%s', got '%s'", serrors.ErrorMismatchBuilderID,
			predicateBuilderID, statement.Predicate.Recipe.Type)
	}

	// Validate the recipe argument type.
	expectedType := "type.googleapis.com/google.devtools.cloudbuild.v1.Build"
	args, ok := statement.Predicate.Recipe.Arguments.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: recipe arguments is not a map", serrors.ErrorInvalidDssePayload)
	}
	ts, err := getAsString(args, "@type")
	if err != nil {
		return "", err
	}

	if ts != expectedType {
		return "", fmt.Errorf("%w: expected '%s', got '%s'", serrors.ErrorMismatchBuilderID,
			expectedType, ts)
	}

	return predicateBuilderID, nil
}

func getAsString(m map[string]interface{}, key string) (string, error) {
	t, ok := m["@type"]
	if !ok {
		return "", fmt.Errorf("%w: '%s' field is absent", serrors.ErrorInvalidDssePayload, key)
	}
	ts, ok := t.(string)
	if !ok {
		return "", fmt.Errorf("%w: '%s' is not a string", serrors.ErrorInvalidDssePayload, key)
	}
	return ts, nil
}

// VerifySubjectDigest verifies the sha256 of the subject.
func (self *Provenance) VerifySubjectDigest(expectedHash string) error {
	if err := self.isVerified(); err != nil {
		return err
	}

	statement := self.verifiedIntotoStatement
	for _, subject := range statement.StatementHeader.Subject {
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

// Verify source URI in provenance statement.
func (self *Provenance) VerifySourceURI(expectedSourceURI string) error {
	if err := self.isVerified(); err != nil {
		return err
	}

	statement := self.verifiedIntotoStatement
	materials := statement.Predicate.Materials
	if len(materials) == 0 {
		return fmt.Errorf("%w: no materials", serrors.ErrorInvalidDssePayload)
	}
	uri := materials[0].URI
	if !strings.HasPrefix(expectedSourceURI, "https://") {
		expectedSourceURI = "https://" + expectedSourceURI
	}
	if !strings.HasPrefix(uri, expectedSourceURI+"/commit/") {
		return fmt.Errorf("%w: expected '%s', got '%s'",
			serrors.ErrorMismatchSource, expectedSourceURI, uri)
	}

	return nil
}

func (self *Provenance) VerifyBranch(branch string) error {
	return fmt.Errorf("%w: GCB branch verification", serrors.ErrorNotSupported)
}

func (self *Provenance) VerifyTag(tag string) error {
	return fmt.Errorf("%w: GCB tag verification", serrors.ErrorNotSupported)
}

func (self *Provenance) VerifyVersionedTag(tag string) error {
	return fmt.Errorf("%w: GCB versioned-tag verification", serrors.ErrorNotSupported)
}

// verifySignatures iterates over all the signatures in the DSSE and verifies them.
// It succeeds if one of them can ne verified.
func (self *Provenance) verifySignatures(prov *provenance) error {
	// Verify the envelope type. It should be an intoto type.
	if prov.Envelope.PayloadType != intoto.PayloadType {
		return fmt.Errorf("%w: expected payload type '%s', got %s",
			serrors.ErrorInvalidDssePayload, intoto.PayloadType, prov.Envelope.PayloadType)
	}

	payload, err := payloadFromEnvelope(&prov.Envelope)
	if err != nil {
		return err
	}

	payloadHash := sha256.Sum256(payload)

	var errs []error
	regex := regexp.MustCompile(`^projects\/verified-builder\/locations\/(.*)\/keyRings\/attestor\/cryptoKeys\/builtByGCB\/cryptoKeyVersions\/1$`)

	for _, sig := range prov.Envelope.Signatures {
		match := regex.FindStringSubmatch(sig.KeyID)
		if len(match) == 2 {
			// Create a public key instance for this region.
			region := match[1]
			pubKey, err := keys.PublicKeyNew(region)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			// Decode the signature.
			rsig, err := base64.RawURLEncoding.DecodeString(sig.Sig)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			// Verify the signature.
			err = pubKey.VerifySignature(payloadHash, rsig)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			var statement v01IntotoStatement
			if err := json.Unmarshal(payload, &statement); err != nil {
				return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
			}
			self.verifiedIntotoStatement = &statement
			self.verifiedProvenance = prov
			fmt.Fprintf(os.Stderr, "Verification succeeded with region key '%s'\n", region)
			return nil
		}
	}

	return fmt.Errorf("%w: %v", serrors.ErrorNoValidSignature, errs)
}

// VerifySignature verifiers the signature for a provenance.
func (self *Provenance) VerifySignature() error {
	if len(self.gcloudProv.ProvenanceSummary.Provenance) == 0 {
		return fmt.Errorf("%w: no provenance found", serrors.ErrorInvalidDssePayload)
	}
	// Iterate over all provenances available.
	var errs []error
	for i := range self.gcloudProv.ProvenanceSummary.Provenance {
		err := self.verifySignatures(&self.gcloudProv.ProvenanceSummary.Provenance[i])
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return nil
	}

	return fmt.Errorf("%w: %v", serrors.ErrorNoValidSignature, errs)
}
