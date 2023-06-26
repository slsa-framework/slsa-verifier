package v1

import (
	"bytes"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
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

// New returns a new Provenance object based on the payload.
func New(payload []byte) (iface.Provenance, error) {
	// Strict unmarshal.
	// NOTE: this supports extensions because they are
	// only used as part of interface{}-defined fields.
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()

	a := &Attestation{}
	if err := dec.Decode(a); err != nil {
		return nil, err
	}

	switch a.Predicate.BuildDefinition.BuildType {
	case common.BYOBBuildTypeV0:
		return &BYOBProvenance{
			provenanceV1: &provenanceV1{
				prov: a,
			},
		}, nil
	case common.ContainerBasedBuildTypeV01Draft:
		return &ContainerBasedProvenance{
			provenanceV1: &provenanceV1{
				prov: a,
			},
		}, nil
	default:
		return nil, fmt.Errorf("%w: %q", serrors.ErrorInvalidBuildType, a.Predicate.BuildDefinition.BuildType)
	}
}
