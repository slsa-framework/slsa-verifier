package v02

import (
	"bytes"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	ghacommon "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
)

// Attestation is a SLSA v0.2 in-toto attestation statement.
type Attestation struct {
	intoto.StatementHeader
	Predicate slsa02.ProvenancePredicate `json:"predicate"`
}

// ProvenanceV02 represents v0.2 provenance.
type ProvenanceV02 interface {
	Predicate() slsa02.ProvenancePredicate
}

type provFunc func(*Attestation) iface.Provenance

// buildTypeMap is a map of builder IDs to supported buildTypes.
var buildTypeMap = map[string]map[string]provFunc{
	ghacommon.GenericDelegatorBuilderID:         {common.BYOBBuildTypeV0: newBYOBProvenance},
	ghacommon.GenericLowPermsDelegatorBuilderID: {common.BYOBBuildTypeV0: newBYOBProvenance},

	ghacommon.GoBuilderID: {
		common.GoBuilderBuildTypeV1:       newLegacyBuilderProvenance,
		common.LegacyBuilderBuildTypeV1:   newLegacyBuilderProvenance,
		common.LegacyGoBuilderBuildTypeV1: newLegacyBuilderProvenance,
	},

	ghacommon.GenericGeneratorBuilderID:   {common.GenericGeneratorBuildTypeV1: newLegacyBuilderProvenance},
	ghacommon.ContainerGeneratorBuilderID: {common.ContainerGeneratorBuildTypeV1: newLegacyBuilderProvenance},

	ghacommon.NpmCLILegacyBuilderID: {common.NpmCLIBuildTypeV1: newLegacyBuilderProvenance},
	ghacommon.NpmCLIHostedBuilderID: {common.NpmCLIBuildTypeV1: newLegacyBuilderProvenance},
	// NOTE: we don't support Npm CLI on self-hosted.
}

// New returns a new Provenance for the given json payload.
func New(builderID string, payload []byte) (iface.Provenance, error) {
	// Strict unmarshal.
	// NOTE: this supports extensions because they are
	// only used as part of interface{}-defined fields.
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()

	a := &Attestation{}
	if err := dec.Decode(a); err != nil {
		return nil, err
	}

	btMap, ok := buildTypeMap[builderID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", serrors.ErrorInvalidBuilderID, builderID)
	}

	pFunc, ok := btMap[a.Predicate.BuildType]
	if !ok {
		return nil, fmt.Errorf("%w: %q for builder ID %q", serrors.ErrorInvalidBuildType, a.Predicate.BuildType, builderID)
	}

	return pFunc(a), nil
}
