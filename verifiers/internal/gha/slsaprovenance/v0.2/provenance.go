package v02

import (
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"
)

// TODO(https://github.com/slsa-framework/slsa-verifier/issues/473): Use a static mapping.
//
//nolint:gochecknoinits
func init() {
	slsaprovenance.ProvenanceMap.Store(
		slsaprovenance.ProvenanceV02Type,
		New)
}

type ProvenanceV02 struct {
	*intoto.ProvenanceStatement
}

// This returns a new, empty instance of the v0.2 provenance.
func New() slsaprovenance.Provenance {
	return &ProvenanceV02{}
}

func (prov *ProvenanceV02) BuilderID() (string, error) {
	return prov.Predicate.Builder.ID, nil
}

func (prov *ProvenanceV02) SourceURI() (string, error) {
	if len(prov.Predicate.Materials) == 0 {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no material")
	}
	return prov.Predicate.Materials[0].URI, nil
}

func (prov *ProvenanceV02) ConfigURI() (string, error) {
	return prov.Predicate.Invocation.ConfigSource.URI, nil
}

func (prov *ProvenanceV02) Subjects() ([]intoto.Subject, error) {
	subj := prov.Subject
	if len(subj) == 0 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}
	return subj, nil
}

func (prov *ProvenanceV02) GetBranch() (string, error) {
	// GetBranch gets the branch from the invocation parameters.
	environment, ok := prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	return slsaprovenance.GetBranch(environment, prov.PredicateType)
}

func (prov *ProvenanceV02) GetTag() (string, error) {
	environment, ok := prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	return slsaprovenance.GetTag(environment, prov.PredicateType)
}

func (prov *ProvenanceV02) GetWorkflowInputs() (map[string]interface{}, error) {
	// Verify it's a workflow_dispatch trigger.
	environment, ok := prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	return slsaprovenance.GetWorkflowInputs(environment, prov.PredicateType)
}
