package v10

// NOTE: Copy of github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1
// This holds an internal copy of in-toto-golang's structs for
// SLSA predicates to handle GCB's incompatibility with the
// published specification.
// Specifically, GCB provenance currently produces a string for
// ProvenancePredicate.Recipe.DefinedInMaterial rather than the SLSA compliant
// signed integer. Because of this, we comment out the field and do not unmarshal
// this in the Go struct. When comparing the envelope with the human-readable
// content, this field is ignored!
// GCB will later add compliant fields in the signed envelope, but NOT in the
// human-readable component. Either disregard comparison between human-readable
// summary and the signed envelope, or use this struct in comparison.

import (
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	intotov1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/iface"
)

const (
	// PredicateSLSAProvenance represents a build provenance for an artifact.
	PredicateSLSAProvenance = intotov1.PredicateSLSAProvenance
	BuildType               = "https://cloud.google.com/build/gcb-buildtypes/google-worker/v1"
)

var BuilderIDs = []string{
	"https://cloudbuild.googleapis.com/GoogleHostedWorker",
}

// ProvenancePredicate is the provenance predicate definition.
type ProvenancePredicate intotov1.ProvenancePredicate

// GCBIntotoTextStatement if for code compatibility with v0.1 code.
type GCBIntotoTextStatement Provenance

// Provenance is GCB provenance.
type Provenance struct {
	intoto.StatementHeader
	Pred ProvenancePredicate `json:"predicate"`
}

func New(payload []byte) (iface.Provenance, error) {
	var provenance Provenance
	if err := json.Unmarshal(payload, &provenance); err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}

	if err := common.ValidateStatementTypes(provenance.StatementHeader.Type, provenance.StatementHeader.PredicateType, PredicateSLSAProvenance); err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	return &provenance, nil
}

func (p *Provenance) Predicate() (any, error) {
	return p.Pred, nil
}

func (p *Provenance) PredicateType() (string, error) {
	return p.StatementHeader.PredicateType, nil
}

func (p *Provenance) Header() (intoto.StatementHeader, error) {
	return p.StatementHeader, nil
}

// BuilderID implements Statement.BuilderID.
func (p *Provenance) BuilderID() (string, error) {
	return p.Pred.RunDetails.Builder.ID, nil
}

// BuildType implements Statement.BuildType.
func (p *Provenance) BuildType() (string, error) {
	return p.Pred.BuildDefinition.BuildType, nil
}

// GetSystemParameters implements Provenance.GetSystemParameters.
func (p *Provenance) GetSystemParameters() (map[string]any, error) {
	sysParams, ok := p.Pred.BuildDefinition.InternalParameters.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: system parameters type", serrors.ErrorInvalidDssePayload)
	}

	return sysParams, nil
}

// SourceTag implements Provenance.SourceTag.
func (p *Provenance) SourceTag() (string, error) {
	sysParams, err := p.GetSystemParameters()
	if err != nil {
		return "", err
	}
	subsTagName, err := getSubstitutionsField(sysParams, "TAG_NAME")
	if err != nil {
		return "", err
	}

	extParams, err := p.externalParameters()
	if err != nil {
		return "", err
	}

	subsTag := "refs/tags/" + subsTagName
	configTag, err := configSourceField(extParams, "ref")
	if err != nil {
		return "", err
	}
	if subsTag != configTag {
		return "", fmt.Errorf("%w: %q != %q", serrors.ErrorInvalidDssePayload, subsTag, configTag)
	}
	return subsTagName, nil
}

func getSubstitutionsField(sysParams map[string]any, name string) (string, error) {
	substitutions, ok := sysParams["systemSubstitutions"]
	if !ok {
		return "", fmt.Errorf("%w: substitution entry %q not found", common.ErrSubstitution, "systemSubstitutions")
	}
	substitutionsMap, ok := substitutions.(map[string]any)
	if !ok {
		return "", fmt.Errorf("%w: no entry '%v' in substitution map", common.ErrSubstitution, "systemSubstitutions")
	}
	value, ok := substitutionsMap[name]
	if !ok {
		return "", fmt.Errorf("%w: no entry '%v' in substitution map", common.ErrSubstitution, name)
	}
	valueStr, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: value '%v' is not a string", common.ErrSubstitution, value)
	}
	return valueStr, nil
}

// SourceBranch implements Provenance.SourceBranch.
func (p *Provenance) SourceBranch() (string, error) {
	// NOTE: for the implementation, verify consistency between
	// repository.ref and substitution's BRANCH. See SourceTag().
	return "", fmt.Errorf("%w: branch verification", serrors.ErrorNotSupported)
}

func (p *Provenance) externalParameters() (map[string]any, error) {
	extParams, ok := p.Pred.BuildDefinition.ExternalParameters.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: system parameters type", serrors.ErrorInvalidDssePayload)
	}
	return extParams, nil
}

// SourceURI implements Provenance.SourceURI.
func (p *Provenance) SourceURI() (string, error) {
	extParams, err := p.externalParameters()
	if err != nil {
		return "", err
	}

	ref, err := configSourceField(extParams, "ref")
	if err != nil {
		return "", err
	}
	repository, err := configSourceField(extParams, "repository")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v@%v", repository, ref), nil
}

func configSourceField(extParams map[string]any, field string) (string, error) {
	// We use externalParameters.buildConfigSource.
	buildConfigSource, ok := extParams["buildConfigSource"]
	if !ok {
		return "", fmt.Errorf("%w: buildConfigSource", serrors.ErrorNotPresent)
	}

	configSource, ok := buildConfigSource.(map[string]any)
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type buildConfigSource")
	}
	field, err := common.GetAsString(configSource, field)
	if err != nil {
		return "", err
	}
	return field, nil
}

// Subjects implements Statement.Subjects.
func (p *Provenance) Subjects() ([]intoto.Subject, error) {
	subj := p.StatementHeader.Subject
	if len(subj) == 0 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}
	return subj, nil
}
