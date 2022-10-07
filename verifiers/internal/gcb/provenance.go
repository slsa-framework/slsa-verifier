package gcb

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/google/go-cmp/cmp"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/slsa-framework/slsa-verifier/options"
	"github.com/slsa-framework/slsa-verifier/verifiers/internal/gcb/keys"
	"github.com/slsa-framework/slsa-verifier/verifiers/utils"
)

var GCBBuilderIDs = []string{
	"https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
	"https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
}

type v01IntotoStatement struct {
	intoto.StatementHeader
	Predicate ProvenancePredicate `json:"predicate"`
}

// The GCB provenance contains a human-readable version of the intoto
// statement, but it is not compliant with the standard. It uses `slsaProvenance`
// instead of `predicate`. For backward compatibility, this has not been fixed
// by the GCB team.
type v01GCBIntotoStatement struct {
	intoto.StatementHeader
	SlsaProvenance ProvenancePredicate `json:"slsaProvenance"`
}

type provenance struct {
	Build struct {
		UnverifiedTextIntotoStatement v01GCBIntotoStatement `json:"intotoStatement"`
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
		return nil, fmt.Errorf("json.Unmarshal gcloud provenance: %w", err)
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

// VerifyTextProvenance verifies the text provenance prepended
// to the provenance.This text mirrors the DSSE payload but is human-readable.
func (self *Provenance) VerifyTextProvenance() error {
	if err := self.isVerified(); err != nil {
		return err
	}

	// Note: there is an additional field `metadata.buildInvocationId` which
	// is not part of the specs but is present. This field is currently ignored during comparison.
	unverifiedTextIntotoStatement := v01IntotoStatement{
		StatementHeader: self.verifiedProvenance.Build.UnverifiedTextIntotoStatement.StatementHeader,
		Predicate:       self.verifiedProvenance.Build.UnverifiedTextIntotoStatement.SlsaProvenance,
	}

	// Note: DeepEqual() has problem with time comparisons: https://github.com/onsi/gomega/issues/264
	// but this should not affect us since both times are supposed to have the same string and
	// they are both taken from a string representation.
	// We do not use cmp.Equal() because it *can* panic and is intended for unit tests only.
	if !reflect.DeepEqual(unverifiedTextIntotoStatement, *self.verifiedIntotoStatement) {
		return fmt.Errorf("%w: diff '%s'", serrors.ErrorMismatchIntoto,
			cmp.Diff(unverifiedTextIntotoStatement, *self.verifiedIntotoStatement))
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
	if statement.StatementHeader.PredicateType != PredicateSLSAProvenance {
		return fmt.Errorf("%w: expected statement predicate type '%s', got '%s'",
			serrors.ErrorInvalidDssePayload, PredicateSLSAProvenance, statement.StatementHeader.PredicateType)
	}

	return nil
}

func isValidBuilderID(id string) error {
	for _, b := range GCBBuilderIDs {
		if id == b {
			return nil
		}
	}
	return serrors.ErrorInvalidBuilderID
}

func validateRecipeType(builderID utils.TrustedBuilderID, recipeType string) error {
	var err error
	v := builderID.Version()
	switch v {
	case "v0.2":
		// In this version, the recipe type should be the same as
		// the builder ID.
		if builderID.String() == recipeType {
			return nil
		}
		err = fmt.Errorf("%w: expected '%s', got '%s'",
			serrors.ErrorInvalidRecipe, builderID.String(), recipeType)

	case "v0.3":
		// In this version, two recipe types are allowed, depending how the
		// build was made. We don't verify the version of the recipes,
		// because it's not super important and would add complexity.
		recipes := []string{
			"https://cloudbuild.googleapis.com/CloudBuildYaml@",
			"https://cloudbuild.googleapis.com/CloudBuildSteps@",
		}
		for _, r := range recipes {
			if strings.HasPrefix(recipeType, r) {
				return nil
			}
		}
		err = fmt.Errorf("%w: expected on of '%s', got '%s'",
			serrors.ErrorInvalidRecipe, strings.Join(recipes, ","), recipeType)
	default:
		err = fmt.Errorf("%w: version '%s'",
			serrors.ErrorInvalidBuilderID, v)
	}

	return err
}

// VerifyBuilder verifies the builder in the DSSE payload:
// - in the recipe type
// - the recipe argument type
// - the predicate builder ID.
func (self *Provenance) VerifyBuilder(builderOpts *options.BuilderOpts) (*utils.TrustedBuilderID, error) {
	if err := self.isVerified(); err != nil {
		return nil, err
	}

	statement := self.verifiedIntotoStatement
	predicateBuilderID := statement.Predicate.Builder.ID

	// Sanity check the builderID.
	if err := isValidBuilderID(predicateBuilderID); err != nil {
		return nil, err
	}

	provBuilderID, err := utils.TrustedBuilderIDNew(predicateBuilderID)
	if err != nil {
		return nil, err
	}

	// Validate with user-provided value.
	if builderOpts != nil && builderOpts.ExpectedID != nil {
		if err := provBuilderID.Matches(*builderOpts.ExpectedID, false); err != nil {
			return nil, err
		}
	}

	// Valiate the recipe type.
	if err := validateRecipeType(*provBuilderID, statement.Predicate.Recipe.Type); err != nil {
		return nil, err
	}

	// Validate the recipe argument type.
	expectedType := "type.googleapis.com/google.devtools.cloudbuild.v1.Build"
	args, ok := statement.Predicate.Recipe.Arguments.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: recipe arguments is not a map", serrors.ErrorInvalidDssePayload)
	}
	ts, err := getAsString(args, "@type")
	if err != nil {
		return nil, err
	}

	if ts != expectedType {
		return nil, fmt.Errorf("%w: expected '%s', got '%s'", serrors.ErrorMismatchBuilderID,
			expectedType, ts)
	}

	return provBuilderID, nil
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
func (self *Provenance) VerifySourceURI(expectedSourceURI string, builderID utils.TrustedBuilderID) error {
	if err := self.isVerified(); err != nil {
		return err
	}

	statement := self.verifiedIntotoStatement
	materials := statement.Predicate.Materials
	if len(materials) == 0 {
		return fmt.Errorf("%w: no materials", serrors.ErrorInvalidDssePayload)
	}
	uri := materials[0].URI

	// It is possible that GCS builds at level 2 use GCS sources, prefixed by gs://.
	if strings.HasPrefix(uri, "https://") && !strings.HasPrefix(expectedSourceURI, "https://") {
		expectedSourceURI = "https://" + expectedSourceURI
	}

	var err error
	v := builderID.Version()
	switch v {
	case "v0.2":
		// In v0.2, it uses format
		// `https://github.com/laurentsimon/gcb-tests/commit/01ce393d04eb6df2a7b2b3e95d4126e687afb7ae`.
		if !strings.HasPrefix(uri, expectedSourceURI+"/commit/") &&
			!strings.HasPrefix(uri, expectedSourceURI+"#") {
			return fmt.Errorf("%w: expected '%s', got '%s'",
				serrors.ErrorMismatchSource, expectedSourceURI, uri)
		}
		// In v0.3, it uses the standard intoto and has the commit sha in its own
		// `digest.sha1` field.
	case "v0.3":
		// The latter case is a versioned GCS source.
		if uri != expectedSourceURI &&
			!strings.HasPrefix(uri, expectedSourceURI+"#") {
			return fmt.Errorf("%w: expected '%s', got '%s'",
				serrors.ErrorMismatchSource, expectedSourceURI, uri)
		}
	default:
		err = fmt.Errorf("%w: version '%s'",
			serrors.ErrorInvalidBuilderID, v)
	}

	return err
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

func decodeSignature(s string) ([]byte, []error) {
	var errs []error
	rsig, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		// No error, return the value.
		return rsig, nil
	}
	errs = append(errs, err)

	rsig, err = base64.URLEncoding.DecodeString(s)
	if err == nil {
		// No error, return the value.
		return rsig, nil
	}
	errs = append(errs, err)

	return nil, errs
}

// verifySignatures iterates over all the signatures in the DSSE and verifies them.
// It succeeds if one of them can be verified.
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
			rsig, es := decodeSignature(sig.Sig)
			if err != nil {
				errs = append(errs, es...)
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
