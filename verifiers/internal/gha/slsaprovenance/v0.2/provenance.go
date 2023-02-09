package v02

import (
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// TODO(https://github.com/slsa-framework/slsa-verifier/issues/473): Use a static mapping.
//
//nolint:gochecknoinits
func init() {
	slsaprovenance.ProvenanceMap.Store(
		"https://slsa.dev/provenance/v0.2",
		New)
}

type ProvenanceV02 struct {
	*intoto.ProvenanceStatement
}

// This returns a new, empty instance of the v0.2 provenance.
func New() slsaprovenance.Provenance {
	return &ProvenanceV02{}
}

func (prov *ProvenanceV02) BuilderID() (string, error) {
	return prov.Predicate.Builder.ID, nil
}

func (prov *ProvenanceV02) SourceURI() (string, error) {
	if len(prov.Predicate.Materials) == 0 {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no material")
	}
	return prov.Predicate.Materials[0].URI, nil
}

func (prov *ProvenanceV02) ConfigURI() (string, error) {
	return prov.Predicate.Invocation.ConfigSource.URI, nil
}

func (prov *ProvenanceV02) Subjects() ([]intoto.Subject, error) {
	subj := prov.Subject
	if len(subj) == 0 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}
	return subj, nil
}

func (prov *ProvenanceV02) GetBranch() (string, error) {
	// GetBranch gets the branch from the invocation parameters.
	environment, ok := prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	refType, err := utils.GetAsString(environment, "github_ref_type")
	if err != nil {
		return "", err
	}

	switch refType {
	case "branch":
		return utils.GetAsString(environment, "github_ref")
	case "tag":
		return getBranchForTag(prov)
	default:
		return "", fmt.Errorf("%w: %s %s", serrors.ErrorInvalidDssePayload,
			"unknown ref type", refType)
	}
}

func (prov *ProvenanceV02) GetTag() (string, error) {
	environment, ok := prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	refType, err := utils.GetAsString(environment, "github_ref_type")
	if err != nil {
		return "", err
	}

	switch refType {
	case "branch":
		return "", nil
	case "tag":
		return utils.GetAsString(environment, "github_ref")
	default:
		return "", fmt.Errorf("%w: %s %s", serrors.ErrorInvalidDssePayload,
			"unknown ref type", refType)
	}
}

func (prov *ProvenanceV02) GetWorkflowInputs() (map[string]interface{}, error) {
	// Verify it's a workflow_dispatch trigger.
	environment, ok := prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	triggerName, err := utils.GetAsString(environment, "github_event_name")
	if err != nil {
		return nil, err
	}
	if triggerName != "workflow_dispatch" {
		return nil, fmt.Errorf("%w: expected 'workflow_dispatch' trigger, got %s",
			serrors.ErrorMismatchWorkflowInputs, triggerName)
	}

	payload, err := getEventPayload(environment)
	if err != nil {
		return nil, err
	}

	payloadInputs, err := getAsAny(payload, "inputs")
	if err != nil {
		return nil, fmt.Errorf("%w: error retrieving 'inputs': %v", serrors.ErrorInvalidDssePayload, err)
	}

	pyldInputs, ok := payloadInputs.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type inputs")
	}
	return pyldInputs, nil
}

func getBranchForTag(prov *ProvenanceV02) (string, error) {
	// First try the base_ref.
	environment, ok := prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	baseRef, err := utils.GetAsString(environment, "github_base_ref")
	if err != nil {
		return "", err
	}

	// This `base_ref` seems to always be "".
	if baseRef != "" {
		return baseRef, nil
	}

	// Look at the event payload instead.
	eventName, err := utils.GetAsString(environment, "github_event_name")
	if err != nil {
		return "", err
	}

	payload, err := getEventPayload(environment)
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

		branch, err := utils.GetAsString(release, "target_commitish")
		if err != nil {
			return "", fmt.Errorf("%w: %s", err, "target_commitish not present")
		}

		return "refs/heads/" + branch, nil
	default:
		return "", nil
	}
}

func getAsAny(environment map[string]any, field string) (any, error) {
	value, ok := environment[field]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("environment type for %s", field))
	}
	return value, nil
}

func getEventPayload(environment map[string]any) (map[string]any, error) {
	eventPayload, ok := environment["github_event_payload"]
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type event payload")
	}

	payload, ok := eventPayload.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type payload")
	}

	return payload, nil
}
