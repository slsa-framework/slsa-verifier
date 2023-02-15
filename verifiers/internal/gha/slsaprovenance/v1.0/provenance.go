package v1

import (
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1.0"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"
)

// TODO(https://github.com/slsa-framework/slsa-verifier/issues/473): Use a static mapping.
//
//nolint:gochecknoinits
func init() {
	slsaprovenance.ProvenanceMap.Store(
		slsaprovenance.ProvenanceV1DraftType,
		New)
}

type ProvenanceV1 struct {
	intoto.StatementHeader
	Predicate     slsa1.ProvenancePredicate `json:"predicate"`
	predicateType string
}

// This returns a new, empty instance of the v0.2 provenance.
func New() slsaprovenance.Provenance {
	return &ProvenanceV1{
		predicateType: slsaprovenance.ProvenanceV1DraftType,
	}
}

func (prov *ProvenanceV1) BuilderID() (string, error) {
	return prov.Predicate.RunDetails.Builder.ID, nil
}

func (prov *ProvenanceV1) SourceURI() (string, error) {
	extParams, ok := prov.Predicate.BuildDefinition.ExternalParameters.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "external parameters type")
	}
	source, ok := extParams["source"]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "external parameters source")
	}
	sourceBytes, err := json.Marshal(source)
	if err != nil {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err)
	}
	var sourceRef slsa1.ArtifactReference
	if err := json.Unmarshal(sourceBytes, &sourceRef); err != nil {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "external parameters source type")
	}
	return sourceRef.URI, nil
}

func (prov *ProvenanceV1) ConfigURI() (string, error) {
	// The source and config are the same for GHA provenance.
	return prov.SourceURI()
}

func (prov *ProvenanceV1) Subjects() ([]intoto.Subject, error) {
	subj := prov.Subject
	if len(subj) == 0 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}
	return subj, nil
}

func (prov *ProvenanceV1) GetBranch() (string, error) {
	// TODO(https://github.com/slsa-framework/slsa-verifier/issues/472): Add GetBranch() support.
	sysParams, ok := prov.Predicate.BuildDefinition.SystemParameters.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}

	return slsaprovenance.GetBranch(sysParams, prov.predicateType)
}

func (prov *ProvenanceV1) GetTag() (string, error) {
	sysParams, ok := prov.Predicate.BuildDefinition.SystemParameters.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}
	return slsaprovenance.GetTag(sysParams, prov.predicateType)
}

func (prov *ProvenanceV1) GetWorkflowInputs() (map[string]interface{}, error) {
	sysParams, ok := prov.Predicate.BuildDefinition.SystemParameters.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}
	return slsaprovenance.GetWorkflowInputs(sysParams, prov.predicateType)
}
