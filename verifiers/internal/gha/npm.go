package gha

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	publishAttestationV01 = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
)

var errrorInvalidAttestations = errors.New("invalid npm attestations")

type attestation struct {
	PredicateType string `json:"predicateType"`
	Bundle        Bundle `json:"bundle"`
}

type Bundle []byte

// NOTE: do not unmarshal the bundle field.
func (b *Bundle) UnmarshalJSON(data []byte) error {
	*b = data
	return nil
}

// getNpmBundles extracts the provenance and publish bundles.
func getNpmBundles(bytes []byte) ([]byte, []byte, error) {
	var attestations []attestation
	if err := json.Unmarshal(bytes, &attestations); err != nil {
		return nil, nil, fmt.Errorf("%w: json.Unmarshal: %v", errrorInvalidAttestations, err)
	}

	if len(attestations) != 2 {
		return nil, nil, fmt.Errorf("%w: invalid number of attestations: %v", errrorInvalidAttestations, len(attestations))
	}

	// // Extract the provenance bundle.
	// provenanceBundle, err := getBundle(attestations[0], slsaprovenance.ProvenanceV02Type)
	// if err != nil {
	// 	return nil, nil, fmt.Errorf("provenance attestation: %w", err)
	// }

	// // Extract the publish bundle.
	// publishBundle, err := getBundle(attestations[1], publishAttestationV01)
	// if err != nil {
	// 	return nil, nil, fmt.Errorf("provenance attestation: %w", err)
	// }

	return attestations[0].Bundle, attestations[1].Bundle, nil
}

// func getBundle(att attestation, perdicateType string) (*bundle_v1.Bundle, error) {
// 	if att.PredicateType != perdicateType {
// 		return nil, fmt.Errorf("%w: invalid predicate type: %v. Expected %v", errrorInvalidAttestations,
// 			att.PredicateType, slsaprovenance.ProvenanceV02Type)
// 	}

// 	var bundle bundle_v1.Bundle
// 	if err := protojson.Unmarshal(att.Bundle, &bundle); err != nil {
// 		return nil, fmt.Errorf("%w: protojson.Unmarshal: %v", errrorInvalidAttestations, err)
// 	}
// 	return &bundle, nil
// }
