package v1

import (
	"errors"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1.0"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"
)

// TODO(asraa): Use a static mapping.
//
//nolint:gochecknoinits
func init() {
	slsaprovenance.ProvenanceMap.Store(
		"https://slsa.dev/provenance/v1.0?draft",
		New)
}

type ProvenanceV1 struct {
	intoto.StatementHeader
	Predicate slsa1.ProvenancePredicate `json:"predicate"`
}

// This returns a new, empty instance of the v0.2 provenance.
func New() slsaprovenance.Provenance {
	return &ProvenanceV1{}
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
	sourceRef, ok := source.(slsa1.ArtifactReference)
	if !ok {
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
	return "", errors.New("unimplemented")
}

func (prov *ProvenanceV1) GetTag() (string, error) {
	return "", errors.New("unimplemented")
}

func (prov *ProvenanceV1) GetWorkflowInputs() (map[string]interface{}, error) {
	return nil, errors.New("unimplemented")
}
