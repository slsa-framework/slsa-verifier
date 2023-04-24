package v1

import (
	"encoding/json"
	"fmt"
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"
)

// TODO(https://github.com/slsa-framework/slsa-verifier/issues/473): Use a static mapping.
//
//nolint:gochecknoinits
func init() {
	slsaprovenance.ProvenanceMap.Store(
		slsa1.PredicateSLSAProvenance,
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
		predicateType: slsa1.PredicateSLSAProvenance,
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
	var sourceRef slsa1.ResourceDescriptor
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
	sysParams, ok := prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}

	return slsaprovenance.GetBranch(sysParams, prov.predicateType)
}

func (prov *ProvenanceV1) GetTag() (string, error) {
	sysParams, ok := prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}
	return slsaprovenance.GetTag(sysParams, prov.predicateType)
}

func (prov *ProvenanceV1) GetWorkflowInputs() (map[string]interface{}, error) {
	sysParams, ok := prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}
	return slsaprovenance.GetWorkflowInputs(sysParams, prov.predicateType)
}

// TODO(https://github.com/slsa-framework/slsa-verifier/issues/566):
// verify the ref and repo as well.
func (prov *ProvenanceV1) GetBuildTriggerPath() (string, error) {
	sysParams, ok := prov.Predicate.BuildDefinition.SystemParameters.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}

	w, ok := sysParams["workflow"]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "workflow parameters type")
	}

	wMap, ok := w.(map[string]string)
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "workflow not a map")
	}

	v, ok := wMap["path"]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no path entry on workflow")
	}
	return v, nil
}

func (prov *ProvenanceV1) GetBuildID() (string, error) {
	return prov.Predicate.RunDetails.BuildMetadata.InvocationID, nil
}

func (prov *ProvenanceV1) GetBuildStartTime() (*time.Time, error) {
	return prov.Predicate.RunDetails.BuildMetadata.StartedOn, nil
}

func (prov *ProvenanceV1) GetBuildFinishTime() (*time.Time, error) {
	return prov.Predicate.RunDetails.BuildMetadata.FinishedOn, nil
}

func (prov *ProvenanceV1) GetNumberResolvedDependencies() (int, error) {
	return len(prov.Predicate.BuildDefinition.ResolvedDependencies), nil
}

func (prov *ProvenanceV1) GetSystemParameters() (map[string]any, error) {
	sysParams, ok := prov.Predicate.BuildDefinition.SystemParameters.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}

	return sysParams, nil
}
