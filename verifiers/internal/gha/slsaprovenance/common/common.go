package common

import (
	"fmt"
	"strings"

	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

const (
	// ProvenanceV02Type is the SLSA v0.2 predicate type.
	ProvenanceV02Type = "https://slsa.dev/provenance/v0.2"

	// ProvenanceV1Type is the SLSA v1.0 predicate type.
	ProvenanceV1Type = slsa1.PredicateSLSAProvenance
)

// GetWorkflowInputs gets the workflow inputs from the GitHub environment map
// and converts the keys to the necessary casing depending on predicate type.
func GetWorkflowInputs(environment map[string]any, upperEnv bool) (map[string]any, error) {
	// Verify it's a workflow_dispatch trigger.
	eventKey, err := convertKey("github_event_name", upperEnv)
	if err != nil {
		return nil, fmt.Errorf("%w: %s",
			serrors.ErrorMismatchWorkflowInputs, err)
	}
	triggerName, err := GetAsString(environment, eventKey)
	if err != nil {
		return nil, err
	}
	if triggerName != "workflow_dispatch" {
		return nil, fmt.Errorf("%w: expected 'workflow_dispatch' trigger, got %s",
			serrors.ErrorMismatchWorkflowInputs, triggerName)
	}

	payload, err := GetEventPayload(environment, upperEnv)
	if err != nil {
		return nil, err
	}

	payloadInputs, err := getAsAny(payload, "inputs")
	if err != nil {
		return nil, fmt.Errorf("%w: error retrieving 'inputs': %v", serrors.ErrorInvalidDssePayload, err)
	}

	pyldInputs, ok := payloadInputs.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type inputs")
	}
	return pyldInputs, nil
}

// GetEventPayload retrieves the GitHub event payload from the environment map
// that contains the GitHub context payload.
func GetEventPayload(environment map[string]any, upperEnv bool) (map[string]any, error) {
	eventPayloadKey, err := convertKey("github_event_payload", upperEnv)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err)
	}
	eventPayload, ok := environment[eventPayloadKey]
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type event payload")
	}

	payload, ok := eventPayload.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type payload")
	}

	return payload, nil
}

func convertKey(key string, upperEnv bool) (string, error) {
	if upperEnv {
		return strings.ToUpper(key), nil
	}
	return key, nil
}

func getAsAny(environment map[string]any, field string) (any, error) {
	value, ok := environment[field]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("environment type for %s", field))
	}
	return value, nil
}

func getBranchForTag(environment map[string]any, upperEnv bool) (string, error) {
	baseRefKey, err := convertKey("github_base_ref", upperEnv)
	if err != nil {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err)
	}

	baseRef, err := GetAsString(environment, baseRefKey)
	if err != nil {
		return "", err
	}

	// This `base_ref` seems to always be "".
	if baseRef != "" {
		return baseRef, nil
	}

	// Look at the event payload instead.
	environmentKey, err := convertKey("github_event_name", upperEnv)
	if err != nil {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err)
	}
	eventName, err := GetAsString(environment, environmentKey)
	if err != nil {
		return "", err
	}

	payload, err := GetEventPayload(environment, upperEnv)
	if err != nil {
		return "", err
	}

	// We don't do that for all triggers because the payload
	// is event-specific. Only `push` events seem to have a `base_ref`, and
	// `release` events specify a branch in `target_commitish`.
	switch eventName {
	case "push":
		value, err := getAsAny(payload, "base_ref")
		if err != nil {
			return "", err
		}

		// The `base_ref` field may be nil if the build was from
		// a specific commit rather than a branch.
		v, ok := value.(string)
		if !ok {
			return "", nil
		}
		return v, nil
	case "release":
		// For a release event, we look for release.target_commitish.
		releasePayload, ok := payload["release"]
		if !ok {
			return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "release absent from payload")
		}

		release, ok := releasePayload.(map[string]any)
		if !ok {
			return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type releasePayload")
		}

		branch, err := GetAsString(release, "target_commitish")
		if err != nil {
			return "", fmt.Errorf("%w: %s", err, "target_commitish not present")
		}

		return "refs/heads/" + branch, nil
	default:
		return "", nil
	}
}

// GetTag returns the triggering event's tag based on the given environment.
func GetTag(environment map[string]any, upperEnv bool) (string, error) {
	refTypeKey, err := convertKey("github_ref_type", upperEnv)
	if err != nil {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err)
	}

	refType, err := GetAsString(environment, refTypeKey)
	if err != nil {
		return "", err
	}

	switch refType {
	case "branch":
		return "", nil
	case "tag":
		refKey, err := convertKey("github_ref", upperEnv)
		if err != nil {
			return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err)
		}
		return GetAsString(environment, refKey)
	default:
		return "", fmt.Errorf("%w: %s %q", serrors.ErrorInvalidDssePayload,
			"unknown ref type", refType)
	}
}

// GetBranch returns the triggering event's branch based on the given environment.
func GetBranch(environment map[string]any, upperEnv bool) (string, error) {
	refTypeKey, err := convertKey("github_ref_type", upperEnv)
	if err != nil {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err)
	}

	refType, err := GetAsString(environment, refTypeKey)
	if err != nil {
		return "", err
	}

	switch refType {
	case "branch":
		refKey, err := convertKey("github_ref", upperEnv)
		if err != nil {
			return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err)
		}
		return GetAsString(environment, refKey)
	case "tag":
		return getBranchForTag(environment, upperEnv)
	default:
		return "", fmt.Errorf("%w: %s %q", serrors.ErrorInvalidDssePayload,
			"unknown ref type", refType)
	}
}

// Exists returns true if the given key exists in the environment.
func Exists(environment map[string]any, field string) bool {
	_, ok := environment[field]
	return ok
}

// GetAsString returns the value in the given environment as a string.
func GetAsString(environment map[string]any, field string) (string, error) {
	value, ok := environment[field]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("environment type for %s", field))
	}

	i, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s '%s'", serrors.ErrorInvalidDssePayload, "environment type string", field)
	}
	return i, nil
}
