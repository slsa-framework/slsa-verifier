package v1

import (
	"fmt"
	"strings"
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// BYOBProvenance is SLSA v1.0 provenance for the slsa-github-generator BYOB build type.
type BYOBProvenance struct {
	prov *intotoAttestation
}

// Predicate implements ProvenanceV02.Predicate.
func (p *BYOBProvenance) Predicate() slsa1.ProvenancePredicate {
	return p.prov.Predicate
}

// BuilderID implements Provenance.BuilderID.
func (p *BYOBProvenance) BuilderID() (string, error) {
	return p.prov.Predicate.RunDetails.Builder.ID, nil
}

// BuildType implements Provenance.BuildType.
func (p *BYOBProvenance) BuildType() (string, error) {
	return p.prov.Predicate.BuildDefinition.BuildType, nil
}

// SourceURI implements Provenance.SourceURI.
func (p *BYOBProvenance) SourceURI() (string, error) {
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
func (p *BYOBProvenance) generatorTriggerInfo() (string, string, string, error) {
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

func (p *BYOBProvenance) builderTriggerInfo() (string, string, string, error) {
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

func (p *BYOBProvenance) triggerInfo() (string, string, string, error) {
	// TODO(#613): Support for generators.
	return p.builderTriggerInfo()
}

// TriggerURI implements Provenance.TriggerURI.
func (p *BYOBProvenance) TriggerURI() (string, error) {
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
func (p *BYOBProvenance) Subjects() ([]intoto.Subject, error) {
	subj := p.prov.Subject
	if len(subj) == 0 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}
	return subj, nil
}

// GetBranch implements Provenance.GetBranch.
func (p *BYOBProvenance) GetBranch() (string, error) {
	sourceURI, err := p.SourceURI()
	if err != nil {
		// Get the value from the internalParameters if there is no source URI.
		sysParams, ok := p.prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "internal parameters type")
		}
		return common.GetBranch(sysParams, true)
	}

	// Returns the branch from the source URI if available.
	_, ref, err := utils.ParseGitURIAndRef(sourceURI)
	if err != nil {
		return "", fmt.Errorf("parsing source uri: %w", err)
	}

	if ref == "" {
		return "", fmt.Errorf("%w: unable to get ref for source %q",
			serrors.ErrorInvalidDssePayload, sourceURI)
	}

	refType, _ := utils.ParseGitRef(ref)
	switch refType {
	case "heads": // branch.
		// NOTE: We return the full git ref.
		return ref, nil
	case "tags":
		// NOTE: If the ref type is a tag we want to try to parse out the branch from the tag.
		sysParams, ok := p.prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "internal parameters type")
		}
		return common.GetBranch(sysParams, true)
	default:
		return "", fmt.Errorf("%w: unknown ref type %q for ref %q",
			serrors.ErrorInvalidDssePayload, refType, ref)
	}
}

// GetTag implements Provenance.GetTag.
func (p *BYOBProvenance) GetTag() (string, error) {
	sourceURI, err := p.SourceURI()
	if err != nil {
		// Get the value from the internalParameters if there is no source URI.
		sysParams, ok := p.prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
		}

		return common.GetTag(sysParams, true)
	}

	// Returns the branch from the source URI if available.
	_, ref, err := utils.ParseGitURIAndRef(sourceURI)
	if err != nil {
		return "", fmt.Errorf("parsing source uri: %w", err)
	}

	if ref == "" {
		return "", fmt.Errorf("%w: unable to get ref for source %q",
			serrors.ErrorInvalidDssePayload, sourceURI)
	}

	refType, _ := utils.ParseGitRef(ref)
	switch refType {
	case "heads": // branch.
		return "", nil
	case "tags":
		// NOTE: We return the full git ref.
		return ref, nil
	default:
		return "", fmt.Errorf("%w: unknown ref type %q for ref %q",
			serrors.ErrorInvalidDssePayload, refType, ref)
	}
}

// GetWorkflowInputs implements Provenance.GetWorkflowInputs.
func (p *BYOBProvenance) GetWorkflowInputs() (map[string]interface{}, error) {
	sysParams, ok := p.prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}
	return common.GetWorkflowInputs(sysParams, true)
}

// GetBuildTriggerPath implements Provenance.GetBuildTriggerPath.
func (p *BYOBProvenance) GetBuildTriggerPath() (string, error) {
	// TODO(#566): verify the ref and repo as well.
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
func (p *BYOBProvenance) GetBuildInvocationID() (string, error) {
	return p.prov.Predicate.RunDetails.BuildMetadata.InvocationID, nil
}

// GetBuildStartTime implements Provenance.GetBuildStartTime.
func (p *BYOBProvenance) GetBuildStartTime() (*time.Time, error) {
	return p.prov.Predicate.RunDetails.BuildMetadata.StartedOn, nil
}

// GetBuildFinishTime implements Provenance.GetBuildFinishTime.
func (p *BYOBProvenance) GetBuildFinishTime() (*time.Time, error) {
	return p.prov.Predicate.RunDetails.BuildMetadata.FinishedOn, nil
}

// GetNumberResolvedDependencies implements Provenance.GetNumberResolvedDependencies.
func (p *BYOBProvenance) GetNumberResolvedDependencies() (int, error) {
	return len(p.prov.Predicate.BuildDefinition.ResolvedDependencies), nil
}

// GetSystemParameters implements Provenance.GetSystemParameters.
func (p *BYOBProvenance) GetSystemParameters() (map[string]any, error) {
	sysParams, ok := p.prov.Predicate.BuildDefinition.InternalParameters.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters type")
	}

	return sysParams, nil
}
