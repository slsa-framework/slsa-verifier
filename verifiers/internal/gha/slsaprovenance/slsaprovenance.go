package slsaprovenance

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

const (
	ProvenanceV02Type = "https://slsa.dev/provenance/v0.2"
)

type Provenance interface {
	// BuilderID returns the builder id in the predicate.
	BuilderID() (string, error)

	// SourceURI is the full URI (including tag) of the source material.
	SourceURI() (string, error)

	// ConfigURI is the full URI (including tag) of the configuration material.
	ConfigURI() (string, error)

	// Subject is the list of intoto subjects in the provenance.
	Subjects() ([]intoto.Subject, error)

	// GetBranch retrieves the branch name of the source from the provenance.
	GetBranch() (string, error)

	// GetTag retrieves the tag of the source from the provenance.
	GetTag() (string, error)

	// Get workflow trigger path.
	GetBuildTriggerPath() (string, error)

	// Get system pararmeters.
	GetSystemParameters() (map[string]any, error)

	// Get build invocation ID.
	GetBuildInvocationID() (string, error)

	// Get build start time.
	GetBuildStartTime() (*time.Time, error)

	// Get build finish time.
	GetBuildFinishTime() (*time.Time, error)

	// Get number of resolved dependencies.
	GetNumberResolvedDependencies() (int, error)

	// GetWorkflowInputs retrieves the inputs from the provenance. Only succeeds for event
	// relevant event types (workflow_inputs).
	GetWorkflowInputs() (map[string]interface{}, error)
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
		return nil, fmt.Errorf("%w: unexpected predicate type '%s'", serrors.ErrorInvalidDssePayload, pred.PredicateType)
	}
	prov := ptype.(func() Provenance)()

	// Strict unmarshal.
	// NOTE: this supports extensions because they are
	// only used as part of interface{}-defined fields.
	dec := json.NewDecoder(bytes.NewReader(pyld))
	dec.DisallowUnknownFields()
	if err := dec.Decode(prov); err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	return prov, nil
}
