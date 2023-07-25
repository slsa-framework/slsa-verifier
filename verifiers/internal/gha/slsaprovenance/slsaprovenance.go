package slsaprovenance

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
	slsav02 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/v0.2"
	slsav1 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/v1.0"
)

// provenanceConstructor creates a new Provenance instance for the given payload as a json Decoder.
type provenanceConstructor func(builderID string, payload []byte) (iface.Provenance, error)

// predicateTypeMap stores the different provenance version types. It is a map of
// predicate type -> ProvenanceConstructor.
var predicateTypeMap = map[string]provenanceConstructor{
	common.ProvenanceV02Type: slsav02.New,
	common.ProvenanceV1Type:  slsav1.New,
}

// ProvenanceFromEnvelope returns a Provenance instance for the given builder
// ID and DSSE Envelope. The builder ID is retrieved from the signing certificate
// rather than from the payload itself in order to support delegated builders.
func ProvenanceFromEnvelope(builderID string, env *dsselib.Envelope) (iface.Provenance, error) {
	if env.PayloadType != intoto.PayloadType {
		return nil, fmt.Errorf("%w: expected payload type %q, got %q",
			serrors.ErrorInvalidDssePayload, intoto.PayloadType, env.PayloadType)
	}

	pyld, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", serrors.ErrorInvalidDssePayload, err)
	}

	// Load the in-toto attestation statement header.
	pred := intoto.StatementHeader{}
	if err := json.Unmarshal(pyld, &pred); err != nil {
		return nil, fmt.Errorf("%w: decoding json: %w", serrors.ErrorInvalidDssePayload, err)
	}

	// Verify the predicate type is one we can handle.
	newProv, ok := predicateTypeMap[pred.PredicateType]
	if !ok {
		return nil, fmt.Errorf("%w: unexpected predicate type %q", serrors.ErrorInvalidDssePayload, pred.PredicateType)
	}
	prov, err := newProv(builderID, pyld)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", serrors.ErrorInvalidDssePayload, err)
	}

	return prov, nil
}
