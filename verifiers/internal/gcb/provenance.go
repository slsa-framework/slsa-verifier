package gcb

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/google/go-cmp/cmp"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/keys"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/iface"
	v01 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/v0.1"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

var GCBBuilderIDs = []string{
	"https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
	"https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
}

var regionalKeyRegex = regexp.MustCompile(`^projects\/verified-builder\/locations\/(.*)\/keyRings\/attestor\/cryptoKeys\/builtByGCB\/cryptoKeyVersions\/1$`)

type provenance struct {
	Build struct {
		UnverifiedTextIntotoStatementV01 v01.GCBIntotoTextStatement `json:"intotoStatement"`
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
	verifiedIntotoStatement *iface.Statement
}

func ProvenanceFromBytes(payload []byte) (*Provenance, error) {
	var prov gloudProvenance
	err := json.Unmarshal(payload, &prov)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", serrors.ErrorInvalidDssePayload, err)
	}

	return &Provenance{
		gcloudProv: &prov,
	}, nil
}

func (p *Provenance) isVerified() error {
	// Check that the signature is verified.
	if p.verifiedIntotoStatement == nil ||
		p.verifiedProvenance == nil {
		return serrors.ErrorNoValidSignature
	}
	return nil
}

func (p *Provenance) GetVerifiedIntotoStatement() ([]byte, error) {
	if err := p.isVerified(); err != nil {
		return nil, err
	}
	d, err := json.Marshal(p.verifiedIntotoStatement)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	return d, nil
}

// VerifyMetadata verifies additional metadata contained in the provenance, which is not part
// of the DSSE payload or headers. It is part of the payload returned by
// `gcloud artifacts docker images describe image:tag --format json --show-provenance`.
func (p *Provenance) VerifyMetadata(provenanceOpts *options.ProvenanceOpts) error {
	if err := p.isVerified(); err != nil {
		return err
	}

	if provenanceOpts == nil {
		return nil
	}
	prov := p.verifiedProvenance

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
func (p *Provenance) VerifySummary(provenanceOpts *options.ProvenanceOpts) error {
	if err := p.isVerified(); err != nil {
		return err
	}

	if provenanceOpts == nil {
		return nil
	}

	// Validate the digest.
	if p.gcloudProv.ImageSummary.Digest != "sha256:"+provenanceOpts.ExpectedDigest {
		return fmt.Errorf("%w: expected summary digest '%s', got '%s'",
			serrors.ErrorMismatchHash, provenanceOpts.ExpectedDigest,
			p.gcloudProv.ImageSummary.Digest)
	}

	// Validate the qualified digest.
	if !strings.HasSuffix(p.gcloudProv.ImageSummary.FullyQualifiedDigest,
		"sha256:"+provenanceOpts.ExpectedDigest) {
		return fmt.Errorf("%w: expected fully qualifiedd digest '%s', got '%s'",
			serrors.ErrorMismatchHash, provenanceOpts.ExpectedDigest,
			p.gcloudProv.ImageSummary.FullyQualifiedDigest)
	}
	return nil
}

// VerifyTextProvenance verifies the text provenance prepended
// to the provenance.This text mirrors the DSSE payload but is human-readable.
func (p *Provenance) VerifyTextProvenance() error {
	if err := p.isVerified(); err != nil {
		return err
	}

	statement := p.verifiedIntotoStatement
	predicate, err := (*statement).Predicate()
	if err != nil {
		return err
	}

	var unverifiedTextIntotoStatement interface{}
	switch v := predicate.(type) {
	case v01.ProvenancePredicate:
		// NOTE: there is an additional field `metadata.buildInvocationId` which
		// is not part of the specs but is present. This field is currently ignored during comparison.
		unverifiedTextIntotoStatement = &v01.IntotoStatement{
			StatementHeader: p.verifiedProvenance.Build.UnverifiedTextIntotoStatementV01.StatementHeader,
			Pred:            p.verifiedProvenance.Build.UnverifiedTextIntotoStatementV01.SlsaProvenance,
		}
	default:
		return fmt.Errorf("%w: unknown %v type", serrors.ErrorInvalidFormat, v)
	}

	// Note: DeepEqual() has problem with time comparisons: https://github.com/onsi/gomega/issues/264
	// but this should not affect us since both times are supposed to have the same string and
	// they are both taken from a string representation.
	// We do not use cmp.Equal() because it *can* panic and is intended for unit tests only.
	if !reflect.DeepEqual(unverifiedTextIntotoStatement, *p.verifiedIntotoStatement) {
		return fmt.Errorf("%w: diff '%s'", serrors.ErrorMismatchIntoto,
			cmp.Diff(unverifiedTextIntotoStatement, *p.verifiedIntotoStatement))
	}

	return nil
}

// VerifyIntotoHeaders verifies the headers are intoto format and the expected
// slsa predicate.
func (p *Provenance) VerifyIntotoHeaders() error {
	if err := p.isVerified(); err != nil {
		return err
	}

	statement := p.verifiedIntotoStatement
	header, err := (*statement).Header()
	if err != nil {
		return err
	}

	predicate, err := (*statement).Predicate()
	if err != nil {
		return err
	}

	var tyIntoto, tyProvenance string
	switch v := predicate.(type) {
	case v01.ProvenancePredicate:
		tyProvenance = v01.PredicateSLSAProvenance
		tyIntoto = v01.StatementInToto
	default:
		return fmt.Errorf("%w: unexpected statement header type '%s'",
			serrors.ErrorInvalidDssePayload, v)
	}

	if header.Type != tyIntoto {
		return fmt.Errorf("%w: expected statement header type '%s', got '%s'",
			serrors.ErrorInvalidDssePayload, tyIntoto, header.Type)
	}

	if header.PredicateType != tyProvenance {
		return fmt.Errorf("%w: expected statement predicate type '%s', got '%s'",
			serrors.ErrorInvalidDssePayload, tyProvenance, header.PredicateType)
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

func validateBuildType(builderID utils.TrustedBuilderID, buildType string) error {
	var err error
	v := builderID.Version()
	switch v {
	// NOTE: buildType is called recipeType in v0.1 specification.
	// Builders with version <= v0.3 use v0.1 specification.
	case "v0.2":
		// In this version, the recipe type should be the same as
		// the builder ID.
		if builderID.String() == buildType {
			return nil
		}
		err = fmt.Errorf("%w: expected '%s', got '%s'",
			serrors.ErrorInvalidRecipe, builderID.String(), buildType)

	case "v0.3":
		// In this version, two recipe types are allowed, depending how the
		// build was made. We don't verify the version of the recipes,
		// because it's not super important and would add complexity.
		recipes := []string{
			"https://cloudbuild.googleapis.com/CloudBuildYaml@",
			"https://cloudbuild.googleapis.com/CloudBuildSteps@",
		}
		for _, r := range recipes {
			if strings.HasPrefix(buildType, r) {
				return nil
			}
		}
		err = fmt.Errorf("%w: expected on of '%s', got '%s'",
			serrors.ErrorInvalidRecipe, strings.Join(recipes, ","), buildType)
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
func (p *Provenance) VerifyBuilder(builderOpts *options.BuilderOpts) (*utils.TrustedBuilderID, error) {
	if err := p.isVerified(); err != nil {
		return nil, err
	}

	statement := p.verifiedIntotoStatement
	predicateBuilderID, err := (*statement).BuilderID()
	if err != nil {
		return nil, err
	}

	// Sanity check the builderID.
	if err := isValidBuilderID(predicateBuilderID); err != nil {
		return nil, err
	}

	provBuilderID, err := utils.TrustedBuilderIDNew(predicateBuilderID, true)
	if err != nil {
		return nil, err
	}

	// Validate with user-provided value.
	if builderOpts != nil && builderOpts.ExpectedID != nil {
		if err := provBuilderID.MatchesLoose(*builderOpts.ExpectedID, false); err != nil {
			return nil, err
		}
	}

	// Valiate the recipe type.
	buildType, err := (*statement).BuildType()
	if err != nil {
		return nil, err
	}
	if err := validateBuildType(*provBuilderID, buildType); err != nil {
		return nil, err
	}

	// Validate the recipe argument type for v0.2 provenance only.
	predicate, err := (*statement).Predicate()
	if err != nil {
		return nil, err
	}
	switch v := predicate.(type) {
	case v01.ProvenancePredicate:
		expectedType := "type.googleapis.com/google.devtools.cloudbuild.v1.Build"
		args, ok := v.Recipe.Arguments.(map[string]interface{})
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
	default:
		return nil, fmt.Errorf("%w: unknown type %v", serrors.ErrorInvalidFormat, v)
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
func (p *Provenance) VerifySubjectDigest(expectedHash string) error {
	if err := p.isVerified(); err != nil {
		return err
	}

	statement := p.verifiedIntotoStatement
	subjects, err := (*statement).Subjects()
	if err != nil {
		return err
	}
	for _, subject := range subjects {
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
func (p *Provenance) VerifySourceURI(expectedSourceURI string, builderID utils.TrustedBuilderID) error {
	if err := p.isVerified(); err != nil {
		return err
	}

	statement := p.verifiedIntotoStatement
	uri, err := (*statement).SourceURI()
	if err != nil {
		return err
	}
	// NOTE: the material URI did not contain 'git+' for GCB versions <= v0.3.
	// A change occurred sometimes in v0.3 witout version bump.
	// Versions >= 0.3 contain the prefix (https://github.com/slsa-framework/slsa-verifier/pull/519).
	uri = strings.TrimPrefix(uri, "git+")

	// It is possible that GCS builds at level 2 use GCS sources, prefixed by gs://.
	if strings.HasPrefix(uri, "https://") && !strings.HasPrefix(expectedSourceURI, "https://") {
		expectedSourceURI = "https://" + expectedSourceURI
	}

	// The build was not configured with a GitHub trigger. Warn.
	if strings.HasPrefix(uri, "gs://") {
		fmt.Fprintf(os.Stderr, `This build was not configured with a GitHub trigger `+
			`and will not match on an expected, version controlled source URI. `+
			`See Cloud Build's documentation on building repositories from GitHub: `+
			`https://cloud.google.com/build/docs/automating-builds/github/build-repos-from-github`)
	}

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

func (p *Provenance) VerifyBranch(branch string) error {
	return fmt.Errorf("%w: GCB branch verification", serrors.ErrorNotSupported)
}

func (p *Provenance) VerifyTag(expectedTag string) error {
	provenanceTag, err := p.getTag()
	if err != nil {
		return fmt.Errorf("%w: %v", serrors.ErrorMismatchTag, err.Error())
	}

	if provenanceTag != expectedTag {
		return fmt.Errorf("%w: expected '%s', got '%s'",
			serrors.ErrorMismatchTag, expectedTag, provenanceTag)
	}
	return nil
}

func (p *Provenance) VerifyVersionedTag(expectedTag string) error {
	provenanceTag, err := p.getTag()
	if err != nil {
		return fmt.Errorf("%w: %v", serrors.ErrorMismatchVersionedTag, err.Error())
	}
	return utils.VerifyVersionedTag(provenanceTag, expectedTag)
}

func (p *Provenance) getTag() (string, error) {
	if err := p.isVerified(); err != nil {
		return "", err
	}

	statement := p.verifiedIntotoStatement
	provenanceTag, err := getSubstitutionsField(*statement, "TAG_NAME")
	if err != nil {
		return "", err
	}

	return provenanceTag, nil
}

func getSubstitutionsField(statement iface.Statement, name string) (string, error) {
	sysParams, err := statement.GetSystemParameters()
	if err != nil {
		return "", err
	}

	value, ok := sysParams[name]
	if !ok {
		return "", fmt.Errorf("%w: no entry '%v' in substitution map", common.ErrSubstitution, name)
	}

	valueStr, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: value '%v' is not a string", common.ErrSubstitution, value)
	}

	return valueStr, nil
}

// verifySignatures iterates over all the signatures in the DSSE and verifies them.
// It succeeds if one of them can be verified.
func (p *Provenance) verifySignatures(prov *provenance) error {
	// Verify the envelope type. It should be an intoto type.
	if prov.Envelope.PayloadType != intoto.PayloadType {
		return fmt.Errorf("%w: expected payload type '%s', got %s",
			serrors.ErrorInvalidDssePayload, intoto.PayloadType, prov.Envelope.PayloadType)
	}

	payload, err := utils.PayloadFromEnvelope(&prov.Envelope)
	if err != nil {
		return err
	}

	payloadHash := sha256.Sum256(payload)
	// Verify the signatures.
	if len(prov.Envelope.Signatures) == 0 {
		return fmt.Errorf("%w: no signatures found in envelope", serrors.ErrorNoValidSignature)
	}

	var errs []error

	for _, sig := range prov.Envelope.Signatures {
		var region string
		if sig.KeyID == keys.GlobalPAEKeyID {
			// If the signature is signed with the global PAE key, use a DSSE verifier
			// to verify the DSSE/PAE-encoded signature.
			region = keys.GlobalPAEPublicKeyName
			globalPaeKey, err := keys.NewGlobalPAEKey()
			if err != nil {
				errs = append(errs, err)
				continue
			}

			err = globalPaeKey.VerifyPAESignature(&prov.Envelope)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		} else if match := regionalKeyRegex.FindStringSubmatch(sig.KeyID); len(match) == 2 {
			// If the signature is signed with a regional key, verify the legacy
			// signing which is over the envelope (not PAE-encoded).
			region = match[1]
			pubKey, err := keys.NewPublicKey(region)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			// Decode the signature.
			rsig, err := utils.DecodeSignature(sig.Sig)
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
		} else {
			continue
		}

		// TODO(#683): try v1.0 verification.
		stmt, err := v01.New(payload)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		p.verifiedIntotoStatement = &stmt
		p.verifiedProvenance = prov
		fmt.Fprintf(os.Stderr, "Verification succeeded with region key '%s'\n", region)
		return nil
	}

	return fmt.Errorf("%w: %v", serrors.ErrorNoValidSignature, errs)
}

// VerifySignature verifiers the signature for a provenance.
func (p *Provenance) VerifySignature() error {
	if len(p.gcloudProv.ProvenanceSummary.Provenance) == 0 {
		return fmt.Errorf("%w: no provenance found", serrors.ErrorInvalidDssePayload)
	}

	// Iterate over all provenances available.
	var errs []error
	for i := range p.gcloudProv.ProvenanceSummary.Provenance {
		err := p.verifySignatures(&p.gcloudProv.ProvenanceSummary.Provenance[i])
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return nil
	}

	return fmt.Errorf("%w: %v", serrors.ErrorNoValidSignature, errs)
}
