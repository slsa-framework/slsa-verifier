package v02

import (
	"bytes"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
)

// intotoAttestation is a SLSA v0.2 in-toto attestation statement.
type intotoAttestation struct {
	intoto.StatementHeader
	Predicate slsa02.ProvenancePredicate `json:"predicate"`
}

// ProvenanceV02 represents v0.2 provenance.
type ProvenanceV02 interface {
	Predicate() slsa02.ProvenancePredicate
}

// New returns a new Provenance for the given json payload.
func New(payload []byte) (iface.Provenance, error) {
	// Strict unmarshal.
	// NOTE: this supports extensions because they are
	// only used as part of interface{}-defined fields.
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()

	a := &intotoAttestation{}
	if err := dec.Decode(a); err != nil {
		return nil, err
	}

	switch {
	case a.Predicate.BuildType == common.BYOBBuildTypeV0:
		return &provenanceV02{
			upperEnv: true,
			prov:     a,
		}, nil
	case a.Predicate.BuildType == common.GoBuilderBuildTypeV1 ||
		a.Predicate.BuildType == common.GenericGeneratorBuildTypeV1 ||
		a.Predicate.BuildType == common.ContainerGeneratorBuildTypeV1 ||
		a.Predicate.BuildType == common.NpmCLIBuildTypeV1 ||
		a.Predicate.BuildType == common.LegacyBuilderBuildTypeV1 ||
		a.Predicate.BuildType == common.LegacyGoBuilderBuildTypeV1:
		return &provenanceV02{
			upperEnv: false,
			prov:     a,
		}, nil
	default:
		return nil, fmt.Errorf("%w: %q", serrors.ErrorInvalidBuildType, a.Predicate.BuildType)
	}
}
