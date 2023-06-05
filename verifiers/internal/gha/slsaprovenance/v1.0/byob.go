package v1

import (
	"fmt"
	"strings"
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
)

var (
	// byobBuildType is the base build type for BYOB delegated builders.
	byobBuildType = "https://github.com/slsa-framework/slsa-github-generator/delegator-generic@v0"

	// containerBasedBuildType is the build type for the container-based builder and is based on BYOB.
	containerBasedBuildType = "https://slsa.dev/container-based-build/v0.1?draft"
)

// BYOBProvenanceV1 is SLSA v1.0 provenance for the slsa-github-generator BYOB build type.
type BYOBProvenanceV1 struct {
	prov *intotoAttestation
}

// Predicate implements ProvenanceV02.Predicate.
func (p *BYOBProvenanceV1) Predicate() slsa1.ProvenancePredicate {
	return p.prov.Predicate
}

// BuilderID implements Provenance.BuilderID.
func (p *BYOBProvenanceV1) BuilderID() (string, error) {
	return p.prov.Predicate.RunDetails.Builder.ID, nil
}

// SourceURI implements Provenance.SourceURI.
func (p *BYOBProvenanceV1) SourceURI() (string, error) {
	// Use resolvedDependencies.
	if len(p.prov.Predicate.BuildDefinition.ResolvedDependencies) == 0 {
		return "", fmt.Errorf("%w: empty resovedDependencies", serrors.ErrorInvalidDssePayload)
	}
	// For now, we use the first resolvedDependency relying on a GHA builder-verifier contract.
	uri := p.prov.Predicate.BuildDefinition.ResolvedDependencies[0].URI
	if uri == "" {
		return "", fmt.Errorf("%w: empty uri", serrors.ErrorMalformedURI)
	}
	return uri, nil
}

// TODO(#613): Support for generators.
//
//nolint:unused
func getValidateKey(m map[string]interface{}, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%w: no %v found", serrors.ErrorInvalidFormat, key)
	}
	vv, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: not a string %v", serrors.ErrorInvalidFormat, v)
	}
	if vv == "" {
		return "", fmt.Errorf("%w: empty %v", serrors.ErrorInvalidFormat, key)
	}
	return vv, nil
}

// TODO(#613): Support for generators.
//
//nolint:unused
func (p *BYOBProvenanceV1) generatorTriggerInfo() (string, string, string, error) {
	// See https://github.com/slsa-framework/github-actions-buildtypes/blob/main/workflow/v1/example.json#L16-L19.
	extParams, ok := p.prov.Predicate.BuildDefinition.ExternalParameters.(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "external parameters type")
	}
	workflow, ok := extParams["workflow"]
	if !ok {
		return "", "", "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "external parameters workflow")
	}
	workflowMap, ok := workflow.(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("%w: %s, type %T", serrors.ErrorInvalidDssePayload, "not a map of interface{}", workflow)
	}
	ref, err := getValidateKey(workflowMap, "ref")
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %v", serrors.ErrorMalformedURI, err)
	}
	repository, err := getValidateKey(workflowMap, "repository")
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %v", serrors.ErrorMalformedURI, err)
	}
	path, err := getValidateKey(workflowMap, "path")
	if err != nil {
		return "", "", "", err
	}
	return repository, ref, path, nil
}

func (p *BYOBProvenanceV1) builderTriggerInfo() (string, string, string, error) {
	sysParams, ok := p.prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "internal parameters type")
	}

	if _, exists := sysParams["GITHUB_WORKFLOW_REF"]; !exists {
		return "", "", "", fmt.Errorf("%w: GITHUB_WORKFLOW_REF", serrors.ErrorNotPresent)
	}

	workflowRef, err := common.GetAsString(sysParams, "GITHUB_WORKFLOW_REF")
	if err != nil {
		return "", "", "", err
	}

	parts := strings.Split(workflowRef, "@")
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("%w: ref: %s", serrors.ErrorInvalidFormat, workflowRef)
	}
	repoAndPath := parts[0]
	ref := parts[1]

	parts = strings.Split(repoAndPath, "/")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("%w: rep and path: %s", serrors.ErrorInvalidFormat, repoAndPath)
	}

	repo := strings.Join(parts[:2], "/")
	path := strings.Join(parts[2:], "/")
	return fmt.Sprintf("git+https://github.com/%s", repo), ref, path, nil
}

func (p *BYOBProvenanceV1) triggerInfo() (string, string, string, error) {
	// TODO(#613): Support for generators.
	return p.builderTriggerInfo()
}

// TriggerURI implements Provenance.TriggerURI.
func (p *BYOBProvenanceV1) TriggerURI() (string, error) {
	repository, ref, _, err := p.triggerInfo()
	if err != nil {
		return "", err
	}
	if repository == "" || ref == "" {
		return "", fmt.Errorf("%w: repository or ref is empty", serrors.ErrorMalformedURI)
	}
	return fmt.Sprintf("%s@%s", repository, ref), nil
}

// Subjects implements Provenance.Subjects.
func (p *BYOBProvenanceV1) Subjects() ([]intoto.Subject, error) {
	subj := p.prov.Subject
	if len(subj) == 0 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}
	return subj, nil
}

// GetBranch implements Provenance.GetBranch.
func (p *BYOBProvenanceV1) GetBranch() (string, error) {
	// TODO(https://github.com/slsa-framework/slsa-verifier/issues/472): Add GetBranch() support.
	sysParams, ok := p.prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "internal parameters type")
	}

	return common.GetBranch(sysParams, true)
}

// GetTag implements Provenance.GetTag.
func (p *BYOBProvenanceV1) GetTag() (string, error) {
	// Get the value from the internalParameters if there is no source URI.
	sysParams, ok := p.prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}

	return common.GetTag(sysParams, true)
}

// GetWorkflowInputs implements Provenance.GetWorkflowInputs.
func (p *BYOBProvenanceV1) GetWorkflowInputs() (map[string]interface{}, error) {
	sysParams, ok := p.prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}
	return common.GetWorkflowInputs(sysParams, true)
}

// GetBuildTriggerPath implements Provenance.GetBuildTriggerPath.
func (p *BYOBProvenanceV1) GetBuildTriggerPath() (string, error) {
	// TODO(https://github.com/slsa-framework/slsa-verifier/issues/566):
	// verify the ref and repo as well.
	sysParams, ok := p.prov.Predicate.BuildDefinition.ExternalParameters.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}

	w, ok := sysParams["workflow"]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "workflow parameters type")
	}

	wMap, ok := w.(map[string]string)
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "workflow not a map")
	}

	v, ok := wMap["path"]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no path entry on workflow")
	}
	return v, nil
}

// GetBuildInvocationID implements Provenance.GetBuildInvocationID.
func (p *BYOBProvenanceV1) GetBuildInvocationID() (string, error) {
	return p.prov.Predicate.RunDetails.BuildMetadata.InvocationID, nil
}

// GetBuildStartTime implements Provenance.GetBuildStartTime.
func (p *BYOBProvenanceV1) GetBuildStartTime() (*time.Time, error) {
	return p.prov.Predicate.RunDetails.BuildMetadata.StartedOn, nil
}

// GetBuildFinishTime implements Provenance.GetBuildFinishTime.
func (p *BYOBProvenanceV1) GetBuildFinishTime() (*time.Time, error) {
	return p.prov.Predicate.RunDetails.BuildMetadata.FinishedOn, nil
}

// GetNumberResolvedDependencies implements Provenance.GetNumberResolvedDependencies.
func (p *BYOBProvenanceV1) GetNumberResolvedDependencies() (int, error) {
	return len(p.prov.Predicate.BuildDefinition.ResolvedDependencies), nil
}

// GetSystemParameters implements Provenance.GetSystemParameters.
func (p *BYOBProvenanceV1) GetSystemParameters() (map[string]any, error) {
	sysParams, ok := p.prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}

	return sysParams, nil
}
