package v02

import (
	"bytes"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
)

var (
	goBuilderBuildType = "https://github.com/slsa-framework/slsa-github-generator/go@v1"

	genericGeneratorBuildType   = "https://github.com/slsa-framework/slsa-github-generator/generic@v1"
	containerGeneratorBuildType = "https://github.com/slsa-framework/slsa-github-generator/container@v1"
	npmCLIBuildType             = "https://github.com/npm/cli/gha@v1"

	// Legacy build types.
	legacyGoBuilderBuildType = "https://github.com/slsa-framework/slsa-github-generator-go@v1"
	legacyBuilderBuildType   = "https://github.com/slsa-framework/slsa-github-generator@v1"

	// byobBuildType is the base build type for BYOB delegated builders.
	byobDelegatorBuildType = "https://github.com/slsa-framework/slsa-github-generator/delegator-generic@v0"
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

// New returns a new Provenance for the given json payload.
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

	switch {
	case a.Predicate.BuildType == byobDelegatorBuildType:
		return &provenanceV02{
			upperEnv: true,
			prov:     a,
		}, nil
	case a.Predicate.BuildType == goBuilderBuildType ||
		a.Predicate.BuildType == genericGeneratorBuildType ||
		a.Predicate.BuildType == containerGeneratorBuildType ||
		a.Predicate.BuildType == npmCLIBuildType ||
		a.Predicate.BuildType == legacyBuilderBuildType ||
		a.Predicate.BuildType == legacyGoBuilderBuildType:
		return &provenanceV02{
			upperEnv: false,
			prov:     a,
		}, nil
	default:
		return nil, fmt.Errorf("%w: unknown buildType: %q", serrors.ErrorInvalidDssePayload, a.Predicate.BuildType)
	}
}
