package v02

import (
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"
)

func init() {
	slsaprovenance.ProvenanceMap.Store(
		"https://slsa.dev/provenance/v0.2",
		New)
}

type Provenance_v02 struct {
	*intoto.ProvenanceStatement
}

func New() slsaprovenance.Provenance {
	return &Provenance_v02{}
}

func (prov *Provenance_v02) BuilderID() string {
	return prov.Predicate.Builder.ID
}

func (prov *Provenance_v02) SourceURI() (string, error) {
	if len(prov.Predicate.Materials) == 0 {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no material")
	}
	return prov.Predicate.Materials[0].URI, nil
}

func (prov *Provenance_v02) ConfigURI() string {
	return prov.Predicate.Invocation.ConfigSource.URI
}

func (prov *Provenance_v02) Subjects() []intoto.Subject {
	return prov.Subject
}

func (prov *Provenance_v02) GetStringFromEnvironment(name string) (string, error) {
	environment, ok := prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}
	val, ok := environment[name]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("environment type for %s", name))
	}
	i, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s '%s'", serrors.ErrorInvalidDssePayload, "environment type string", name)
	}
	return i, nil
}

func (prov *Provenance_v02) GetAnyFromEnvironment(name string) (interface{}, error) {
	environment, ok := prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}
	val, ok := environment[name]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("environment type for %s", name))
	}
	return val, nil
}

func (prov *Provenance_v02) GetInputs() (map[string]interface{}, error) {
	eventPayload, err := prov.GetAnyFromEnvironment("github_event_payload")
	if err != nil {
		return nil, err
	}

	payload, ok := eventPayload.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type payload")
	}

	payloadInputs, ok := payload["inputs"]
	if !ok {
		return nil, fmt.Errorf("%w: error retrieving 'inputs': %v", serrors.ErrorInvalidDssePayload, err)
	}

	pyldInputs, ok := payloadInputs.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type inputs")
	}
	return pyldInputs, nil
}
