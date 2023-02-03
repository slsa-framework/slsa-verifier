package slsaprovenance

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

type Provenance interface {
	// BuilderID returns the builder id in the predicate.
	BuilderID() string

	// SourceURI is the full URI (including tag) of the source material.
	SourceURI() (string, error)

	// ConfigURI is the full URI (including tag) of the configuration material.
	ConfigURI() string

	// Subject is the list of intoto subjects in the provenance.
	Subjects() []intoto.Subject

	// GetStringFromEnvironment retrieves a string parameter from the environment
	// attested to in the provenance.
	GetStringFromEnvironment(name string) (string, error)

	// GetAnyFromEnvironment retrieves an object parameter from the environment
	// attested to in the provenance.
	GetAnyFromEnvironment(name string) (interface{}, error)

	// GetInputs retrieves the inputs from the provenance. Only succeeds for event
	// relevant event types (workflow_inputs).
	GetInputs() (map[string]interface{}, error)
}

// ProvenanceMap stores the different provenance version types.
var ProvenanceMap sync.Map

// Provenance interface that each type may implement.
func ProvenanceFromEnvelope(env *dsselib.Envelope) (Provenance, error) {
	if env.PayloadType != "application/vnd.in-toto+json" {
		return nil, fmt.Errorf("%w: expected payload type 'application/vnd.in-toto+json', got '%s'",
			serrors.ErrorInvalidDssePayload, env.PayloadType)
	}
	pyld, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}

	// Get the predicateType, a required field.
	pred := struct {
		PredicateType string `json:"predicateType"`
	}{}
	if err := json.Unmarshal(pyld, &pred); err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}

	// Load the appropriate structure and unmarshal.
	ptype, ok := ProvenanceMap.Load(pred.PredicateType)
	if !ok {
		return nil, fmt.Errorf("%w: %s %s", serrors.ErrorInvalidDssePayload, "unexpected predicate type ", pred.PredicateType)
	}
	prov := ptype.(func() Provenance)()

	if err := json.Unmarshal(pyld, prov); err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	return prov, nil
}
