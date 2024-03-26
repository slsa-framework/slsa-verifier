package gcb

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"golang.org/x/exp/slices"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/keys"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/iface"
	v01 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/v0.1"
	v10 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/v1.0"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

type provenance struct {
	Build struct {
		UnverifiedTextIntotoStatementV01 v01.GCBIntotoTextStatement `json:"intotoStatement"`
		UnverifiedTextIntotoStatementV10 v10.GCBIntotoTextStatement `json:"inTotoSlsaProvenanceV1"`
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
	gcloudProv         *gloudProvenance
	verifiedProvenance *provenance
	verifiedStatement  iface.Provenance
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
	if p.verifiedStatement == nil || p.verifiedProvenance == nil {
		return serrors.ErrorNoValidSignature
	}
	return nil
}

func (p *Provenance) GetVerifiedIntotoStatement() ([]byte, error) {
	if err := p.isVerified(); err != nil {
		return nil, err
	}
	d, err := json.Marshal(p.verifiedStatement)
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

	predicateType, err := p.verifiedStatement.PredicateType()
	if err != nil {
		return err
	}

	var unverifiedTextIntotoStatement interface{}
	switch predicateType {
	case v10.PredicateSLSAProvenance:
		unverifiedTextIntotoStatement = &v10.Provenance{
			StatementHeader: p.verifiedProvenance.Build.UnverifiedTextIntotoStatementV10.StatementHeader,
			Pred:            p.verifiedProvenance.Build.UnverifiedTextIntotoStatementV10.Pred,
		}
	case v01.PredicateSLSAProvenance:
		// NOTE: there is an additional field `metadata.buildInvocationId` which
		// is not part of the specs but is present. This field is currently ignored during comparison.
		unverifiedTextIntotoStatement = &v01.Provenance{
			StatementHeader: p.verifiedProvenance.Build.UnverifiedTextIntotoStatementV01.StatementHeader,
			Pred:            p.verifiedProvenance.Build.UnverifiedTextIntotoStatementV01.SlsaProvenance,
		}
	default:
		return fmt.Errorf("%w: unknown %v type", serrors.ErrorInvalidFormat, predicateType)
	}

	// Note: DeepEqual() has problem with time comparisons: https://github.com/onsi/gomega/issues/264
	// but this should not affect us since both times are supposed to have the same string and
	// they are both taken from a string representation.
	// We do not use cmp.Equal() because it *can* panic and is intended for unit tests only.
	if !reflect.DeepEqual(unverifiedTextIntotoStatement, p.verifiedStatement) {
		return fmt.Errorf("%w: \nunverified: %v, \nverified: %v", serrors.ErrorMismatchIntoto,
			unverifiedTextIntotoStatement, p.verifiedStatement)
	}

	return nil
}

func (p *Provenance) validateBuilderID(id string) error {
	predicateType, err := p.verifiedStatement.PredicateType()
	if err != nil {
		return err
	}
	var builders []string
	switch predicateType {
	case v01.PredicateSLSAProvenance:
		builders = v01.BuilderIDs
	case v10.PredicateSLSAProvenance:
		builders = v10.BuilderIDs
	default:
		return fmt.Errorf("%w: unknown predicate type: %v", serrors.ErrorInvalidDssePayload, predicateType)
	}
	for _, b := range builders {
		if id == b {
			return nil
		}
	}
	return serrors.ErrorInvalidBuilderID
}

func validatebuildTypeV01(builderID utils.TrustedBuilderID, buildType string) error {
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

func validatebuildTypeV10(builderID utils.TrustedBuilderID, buildType string) error {
	if buildType != v10.BuildType {
		return fmt.Errorf("%w: %v", serrors.ErrorInvalidBuildType, buildType)
	}
	return nil
}

func validateBuildType(builderID utils.TrustedBuilderID, buildType string) error {
	// v0.1 provenance.
	if slices.Contains(v01.BuilderIDs, builderID.String()) {
		return validatebuildTypeV01(builderID, buildType)
	}

	// v1.0 provenance.
	if slices.Contains(v10.BuilderIDs, builderID.String()) {
		return validatebuildTypeV10(builderID, buildType)
	}
	return fmt.Errorf("%w: %v", serrors.ErrorInvalidBuilderID, builderID.String())
}

// VerifyBuilder verifies the builder in the DSSE payload:
// - in the recipe type
// - the recipe argument type
// - the predicate builder ID.
func (p *Provenance) VerifyBuilder(builderOpts *options.BuilderOpts) (*utils.TrustedBuilderID, error) {
	if err := p.isVerified(); err != nil {
		return nil, err
	}

	statement := p.verifiedStatement
	predicateBuilderID, err := statement.BuilderID()
	if err != nil {
		return nil, err
	}

	// Sanity check the builderID.
	if err := p.validateBuilderID(predicateBuilderID); err != nil {
		return nil, err
	}

	predicateType, err := statement.PredicateType()
	if err != nil {
		return nil, err
	}

	var provBuilderID *utils.TrustedBuilderID
	switch predicateType {
	case v01.PredicateSLSAProvenance:
		provBuilderID, err = utils.TrustedBuilderIDNew(predicateBuilderID, true)
	case v10.PredicateSLSAProvenance:
		// v1.0 has no builder version.
		provBuilderID, err = utils.TrustedBuilderIDNew(predicateBuilderID, false)
	default:
		return nil, fmt.Errorf("%w: unknown predicate type %v", serrors.ErrorInvalidFormat, predicateType)
	}
	if err != nil {
		return nil, err
	}

	// Validate with user-provided value.
	if builderOpts != nil && builderOpts.ExpectedID != nil {
		if err := provBuilderID.MatchesLoose(*builderOpts.ExpectedID, false); err != nil {
			return nil, err
		}
	}

	buildType, err := statement.BuildType()
	if err != nil {
		return nil, err
	}
	// Validate the build type.
	if err := validateBuildType(*provBuilderID, buildType); err != nil {
		return nil, err
	}

	// Validate the recipe argument type for v0.2 provenance only.
	predicate, err := statement.Predicate()
	if err != nil {
		return nil, err
	}
	switch v := predicate.(type) {
	case v10.ProvenancePredicate:
		if predicateType != v10.PredicateSLSAProvenance {
			return nil, fmt.Errorf("%w: expected %q, got %q", serrors.ErrorInvalidFormat, v10.PredicateSLSAProvenance, predicateType)
		}
	case v01.ProvenancePredicate:
		if predicateType != v01.PredicateSLSAProvenance {
			return nil, fmt.Errorf("%w: expected %q, got %q", serrors.ErrorInvalidFormat, v01.PredicateSLSAProvenance, predicateType)
		}
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

	subjects, err := p.verifiedStatement.Subjects()
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

func verifySourceURIV01(builderID utils.TrustedBuilderID, provenanceURI, expectedSourceURI string) error {
	var err error
	v := builderID.Version()
	switch v {
	case "v0.2":
		// In v0.2, it uses format
		// `https://github.com/laurentsimon/gcb-tests/commit/01ce393d04eb6df2a7b2b3e95d4126e687afb7ae`.
		// The latter case is a versioned GCS source which looks like
		// `"gs://damith-sds_cloudbuild/source/1665165360.279777-955d1904741e4bbeb3461080299e929a.tgz#1665165361152729"`.
		if !strings.HasPrefix(provenanceURI, expectedSourceURI+"/commit/") &&
			!strings.HasPrefix(provenanceURI, expectedSourceURI+"#") {
			return fmt.Errorf("%w: expected '%s', got '%s'",
				serrors.ErrorMismatchSource, expectedSourceURI, provenanceURI)
		}
	case "v0.3":
		// In v0.3, it uses the standard intoto and has the commit sha in its own `digest.sha1` field.
		// The latter case is a versioned GCS source which looks like
		// `"gs://damith-sds_cloudbuild/source/1665165360.279777-955d1904741e4bbeb3461080299e929a.tgz#1665165361152729"`.
		if provenanceURI != expectedSourceURI &&
			!strings.HasPrefix(provenanceURI, expectedSourceURI+"#") {
			return fmt.Errorf("%w: expected '%s', got '%s'",
				serrors.ErrorMismatchSource, expectedSourceURI, provenanceURI)
		}
	default:
		err = fmt.Errorf("%w: version '%s'",
			serrors.ErrorInvalidBuilderID, v)
	}

	return err
}

func verifySourceURIV10(builderID utils.TrustedBuilderID, provenanceURI, expectedSourceURI string) error {
	parts := strings.Split(provenanceURI, "@")
	if len(parts) != 2 {
		return fmt.Errorf("%w: no version found in '%v'",
			serrors.ErrorInvalidFormat, provenanceURI)
	}
	if parts[0] != expectedSourceURI {
		return fmt.Errorf("%w: expected '%s', got '%s'",
			serrors.ErrorMismatchSource, expectedSourceURI, parts[0])
	}
	return nil
}

// Verify source URI in provenance statement.
func (p *Provenance) VerifySourceURI(expectedSourceURI string, builderID utils.TrustedBuilderID) error {
	if err := p.isVerified(); err != nil {
		return err
	}

	statement := p.verifiedStatement
	uri, err := statement.SourceURI()
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

	predicateType, err := statement.PredicateType()
	if err != nil {
		return err
	}

	switch predicateType {
	case v10.PredicateSLSAProvenance:
		return verifySourceURIV10(builderID, uri, expectedSourceURI)
	case v01.PredicateSLSAProvenance:
		return verifySourceURIV01(builderID, uri, expectedSourceURI)
	default:
		return fmt.Errorf("%w: unknown predicate type: %v", serrors.ErrorInvalidFormat, predicateType)
	}
}

func (p *Provenance) VerifyBranch(branch string) error {
	if err := p.isVerified(); err != nil {
		return err
	}

	provBranch, err := p.verifiedStatement.SourceBranch()
	if err != nil {
		return err
	}
	if provBranch != branch {
		return fmt.Errorf("%w: expected branch %q, got %q",
			serrors.ErrorNotSupported, branch, provBranch)
	}
	return nil
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

	return p.verifiedStatement.SourceTag()
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
		var keyName string

		// Global PAE keys.
		if sig.KeyID == keys.V10GlobalPAEKeyID || sig.KeyID == keys.V01GlobalPAEKeyID {
			// Global key for v1.0 or v0.1.
			// If the signature is signed with the global PAE key, use a DSSE verifier
			// to verify the DSSE/PAE-encoded signature.
			globalPaeKey, err := keys.NewGlobalPAEKey(sig.KeyID)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			err = globalPaeKey.VerifyPAESignature(&prov.Envelope)
			if err != nil {
				errs = append(errs, fmt.Errorf("%w: key %q", err, globalPaeKey.Name()))
				continue
			}
			// Success.
			keyName = globalPaeKey.Name()
		} else if match := v01.RegionalKeyRegex.FindStringSubmatch(sig.KeyID); len(match) == 2 {
			// Regional key for v0.1.
			// If the signature is signed with a regional key, verify the legacy
			// signing which is over the envelope (not PAE-encoded).
			pubKey, err := keys.NewPublicKey(match[1])
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
			// Success.
			keyName = match[1]
		} else {
			continue
		}

		// Success.
		var stmt iface.Provenance
		if sig.KeyID == keys.V10GlobalPAEKeyID {
			// v1.0 provenance.
			stmt, err = v10.New(payload)
		} else {
			// v0.1 provenance.
			// kkeys.V01GlobalPAEKeyID or regional key.
			stmt, err = v01.New(payload)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}

		p.verifiedStatement = stmt
		p.verifiedProvenance = prov
		fmt.Fprintf(os.Stderr, "Verification succeeded with key %q\n", keyName)
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
