package slsaprovenance

import (
	"fmt"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

// GetWorkflowInputs gets the workflow inputs from the GitHub environment map
// and converts the keys to the necessary casing depending on predicate type.
func GetWorkflowInputs(environment map[string]any) (map[string]any, error) {
	// Verify it's a workflow_dispatch trigger.
	triggerName, err := gitHubEnvAsString(environment, "event_name")
	if err != nil {
		return nil, err
	}
	if triggerName != "workflow_dispatch" {
		return nil, fmt.Errorf("%w: expected 'workflow_dispatch' trigger, got %s",
			serrors.ErrorMismatchWorkflowInputs, triggerName)
	}

	payload, err := GetEventPayload(environment)
	if err != nil {
		return nil, err
	}

	payloadInputs, err := getAsAny(payload, "inputs")
	if err != nil {
		return nil, fmt.Errorf("%w: error retrieving 'inputs': %v", serrors.ErrorInvalidDssePayload, err)
	}

	pyldInputs, ok := payloadInputs.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: parameters type inputs", serrors.ErrorInvalidDssePayload)
	}
	return pyldInputs, nil
}

// GetEventPayload retrieves the GitHub event payload from the environment map
// that contains the GitHub context payload.
func GetEventPayload(environment map[string]any) (map[string]any, error) {
	eventPayload, err := gitHubEnvAsAny(environment, "event_payload")
	if err != nil {
		return nil, err
	}

	payload, ok := eventPayload.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: parameters type payload", serrors.ErrorInvalidDssePayload)
	}

	return payload, nil
}

func getBranchForTag(environment map[string]any) (string, error) {
	baseRef, err := gitHubEnvAsString(environment, "base_ref")
	if err != nil {
		return "", err
	}

	// This `base_ref` seems to always be "".
	if baseRef != "" {
		return baseRef, nil
	}

	// Look at the event payload instead.
	eventName, err := gitHubEnvAsString(environment, "event_name")
	if err != nil {
		return "", err
	}

	payload, err := GetEventPayload(environment)
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

		release, ok := releasePayload.(map[string]interface{})
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

// GetTag returns the event tag if the ref_type is 'tag'. Returns "" if ref_type is 'branch'.
func GetTag(environment map[string]any) (string, error) {
	refType, err := gitHubEnvAsString(environment, "ref_type")
	if err != nil {
		return "", err
	}

	switch refType {
	case "branch":
		return "", nil
	case "tag":
		return gitHubEnvAsString(environment, "ref")
	default:
		return "", fmt.Errorf("%w: %s %s", serrors.ErrorInvalidDssePayload,
			"unknown ref type", refType)
	}
}

// GetBranch returns the triggering event's branch.
func GetBranch(environment map[string]any) (string, error) {
	refType, err := gitHubEnvAsString(environment, "ref_type")
	if err != nil {
		return "", err
	}

	switch refType {
	case "branch":
		return gitHubEnvAsString(environment, "ref")
	case "tag":
		return getBranchForTag(environment)
	default:
		return "", fmt.Errorf("%w: unknown ref type: %s", serrors.ErrorInvalidDssePayload, refType)
	}
}

// Exists returns true if the given field exists in the environment.
func Exists(environment map[string]any, field string) bool {
	_, ok := environment[field]
	return ok
}

func getAsAny(environment map[string]any, field string) (any, error) {
	value, ok := environment[field]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("environment type for %s", field))
	}
	return value, nil
}

// gitHubEnvAsString returns a GITHUB_ environment variable from the given map with the
// key being either uppercase or lowercase.
func gitHubEnvAsString(environment map[string]any, field string) (string, error) {
	value, err := gitHubEnvAsAny(environment, field)
	if err != nil {
		return "", err
	}

	i, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q is not a string", serrors.ErrorInvalidDssePayload, field)
	}
	return i, nil
}

// gitHubEnvAsAny returns a GITHUB_ environment variable from the given map with the
// key being either uppercase or lowercase.
func gitHubEnvAsAny(environment map[string]any, field string) (any, error) {
	key := `github_` + field
	value, ok := environment[strings.ToLower(key)]
	if !ok {
		value, ok = environment[strings.ToUpper(key)]
		if !ok {
			return "", fmt.Errorf("%w: missing value for %q", serrors.ErrorInvalidDssePayload, strings.ToLower(key))
		}
	}
	return value, nil
}

// GetAsString returns the given environment value as a string.
func GetAsString(environment map[string]any, field string) (string, error) {
	value, ok := environment[field]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("missing value for %q", field))
	}

	i, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q is not a string", serrors.ErrorInvalidDssePayload, field)
	}
	return i, nil
}
