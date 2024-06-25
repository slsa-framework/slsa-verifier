package vsa10

import (
	"encoding/json"
	"fmt"
	"time"

	intotoGolang "github.com/in-toto/in-toto-golang/in_toto"
	intotoCommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

const PredicateType = "https://slsa.dev/verification_summary/v1"

// VSA is a struct that represents a VSA statement.
// spec: https://slsa.dev/spec/v1.0/verification_summary.
// Idealy, we use "github.com/in-toto/attestation/go/predicates/vsa/v1"'s VerfificationSummary,
// but it currently does not correctly implement some fields according to spec, such as VerifiedLevels.
type VSA struct {
	intotoGolang.StatementHeader
	// Predicate is the VSA predicate.
	Predicate Predicate `json:"predicate"`
}

// Predicate is the VSA predicate.
type Predicate struct {
	Verifier           Verifier                          `json:"verifier"`
	TimeVerified       time.Time                         `json:"timeVerified"`
	ResourceURI        string                            `json:"resourceUri"`
	Policy             intotoCommon.ProvenanceMaterial   `json:"policy"`
	InputAttestations  []intotoCommon.ProvenanceMaterial `json:"inputAttestations"`
	VerificationResult string                            `json:"verificationResult"`
	VerifiedLevels     []string                          `json:"verifiedLevels"`
	DependecyLevels    map[string]int                    `json:"dependencyLevels"`
	SlsaVersion        string                            `json:"slsaVersion"`
}

// Verifier is the VSA verifier.
type Verifier struct {
	ID      string            `json:"id"`
	Version map[string]string `json:"version"`
}

// VSAFromStatement creates a VSA from a statement.
func VSAFromStatement(statement *intotoGolang.Statement) (*VSA, error) {
	if statement.PredicateType != PredicateType {
		return nil, fmt.Errorf("%w: expected predicate type %q, got %q", serrors.ErrorInvalidDssePayload, PredicateType, statement.PredicateType)
	}
	vsaBytes, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err)
	}
	var vsa VSA
	if err := json.Unmarshal(vsaBytes, &vsa); err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err)
	}
	return &vsa, nil
}
