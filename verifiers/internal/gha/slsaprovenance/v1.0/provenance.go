package v1

import (
	"bytes"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	ghacommon "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
)

// Attestation is an in-toto SLSA v1.0 attestation statement.
type Attestation struct {
	intoto.StatementHeader
	Predicate slsa1.ProvenancePredicate `json:"predicate"`
}

// ProvenanceV1 represents v1.0 provenance.
type ProvenanceV1 interface {
	Predicate() slsa1.ProvenancePredicate
}

type provFunc func(*Attestation) iface.Provenance

func newBYOB(a *Attestation) iface.Provenance {
	return &BYOBProvenance{
		provenanceV1: &provenanceV1{
			prov: a,
		},
	}
}

func newContainerBased(a *Attestation) iface.Provenance {
	return &ContainerBasedProvenance{
		provenanceV1: &provenanceV1{
			prov: a,
		},
	}
}

// buildTypeMap is a map of builder IDs to supported buildTypes.
var buildTypeMap = map[string]map[string]provFunc{
	ghacommon.GenericDelegatorBuilderID:         {common.BYOBBuildTypeV0: newBYOB},
	ghacommon.GenericLowPermsDelegatorBuilderID: {common.BYOBBuildTypeV0: newBYOB},

	common.ContainerBasedBuilderID: {common.ContainerBasedBuildTypeV01Draft: newContainerBased},
}

// New returns a new Provenance object based on the payload.
func New(builderID string, payload []byte) (iface.Provenance, error) {
	// Strict unmarshal.
	// NOTE: this supports extensions because they are
	// only used as part of interface{}-defined fields.
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()

	a := &Attestation{}
	if err := dec.Decode(a); err != nil {
		return nil, fmt.Errorf("%w: %w", serrors.ErrorInvalidDssePayload, err)
	}

	btMap, ok := buildTypeMap[builderID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", serrors.ErrorInvalidBuilderID, builderID)
	}

	provFunc, ok := btMap[a.Predicate.BuildDefinition.BuildType]
	if !ok {
		return nil, fmt.Errorf("%w: %q for builder ID %q", serrors.ErrorInvalidBuildType, a.Predicate.BuildDefinition.BuildType, builderID)
	}

	return provFunc(a), nil
}
