package v02

import (
	"fmt"
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
)

var (
	goBuilderBuildType = "https://github.com/slsa-framework/slsa-github-generator/go@v1"

	genericGeneratorBuildType   = "https://github.com/slsa-framework/slsa-github-generator/generic@v1"
	containerGeneratorBuildType = "https://github.com/slsa-framework/slsa-github-generator/container@v1"
	npmCLIBuildType             = "https://github.com/npm/cli/gha@v1"

	// Legacy build types.
	legacyGoBuilderBuildType = "https://github.com/slsa-framework/slsa-github-generator-go@v1"
	legacyBuilderBuildType   = "https://github.com/slsa-framework/slsa-github-generator@v1"

	// genericGHABuildType is used by some tests.
	// TODO: Update tests to use a real buildType.
	genericGHABuildType = "https://github.com/Attestations/GitHubActionsWorkflow@v1"
)

// GenericProvenanceV02 represents SLSA v0.2 provenance for the
// slsa-github-generator Go builder, generic generator, container generator, and npm CLI.
type GenericProvenanceV02 struct {
	prov *intotoAttestation
}

// Predicate implements ProvenanceV02.Predicate.
func (p *GenericProvenanceV02) Predicate() slsa02.ProvenancePredicate {
	return p.prov.Predicate
}

// BuilderID implements Provenance.BuilderID.
func (p *GenericProvenanceV02) BuilderID() (string, error) {
	return p.prov.Predicate.Builder.ID, nil
}

// SourceURI implements Provenance.SourceURI.
func (p *GenericProvenanceV02) SourceURI() (string, error) {
	if len(p.prov.Predicate.Materials) == 0 {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no material")
	}
	uri := p.prov.Predicate.Materials[0].URI
	if uri == "" {
		return "", fmt.Errorf("%w: empty uri", serrors.ErrorMalformedURI)
	}

	return uri, nil
}

// TriggerURI implements Provenance.TriggerURI.
func (p *GenericProvenanceV02) TriggerURI() (string, error) {
	uri := p.prov.Predicate.Invocation.ConfigSource.URI
	if uri == "" {
		return "", fmt.Errorf("%w: empty uri", serrors.ErrorMalformedURI)
	}
	return uri, nil
}

// Subjects implements Provenance.Subjects.
func (p *GenericProvenanceV02) Subjects() ([]intoto.Subject, error) {
	subj := p.prov.Subject
	if len(subj) == 0 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}
	return subj, nil
}

// GetBranch implements Provenance.GetBranch.
func (p *GenericProvenanceV02) GetBranch() (string, error) {
	environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	return common.GetBranch(environment, common.ProvenanceV02Type)
}

// GetTag implements Provenance.GetTag.
func (p *GenericProvenanceV02) GetTag() (string, error) {
	environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	return common.GetTag(environment, common.ProvenanceV02Type)
}

// GetWorkflowInputs implements Provenance.GetWorkflowInputs.
func (p *GenericProvenanceV02) GetWorkflowInputs() (map[string]interface{}, error) {
	// Verify it's a workflow_dispatch trigger.
	environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	return common.GetWorkflowInputs(environment, common.ProvenanceV02Type)
}

// GetBuildTriggerPath implements Provenance.GetBuildTriggerPath.
func (p *GenericProvenanceV02) GetBuildTriggerPath() (string, error) {
	return p.prov.Predicate.Invocation.ConfigSource.EntryPoint, nil
}

// GetBuildInvocationID implements Provenance.GetBuildInvocationID.
func (p *GenericProvenanceV02) GetBuildInvocationID() (string, error) {
	if p.prov.Predicate.Metadata == nil {
		return "", nil
	}
	return p.prov.Predicate.Metadata.BuildInvocationID, nil
}

// GetBuildStartTime implements Provenance.GetBuildStartTime.
func (p *GenericProvenanceV02) GetBuildStartTime() (*time.Time, error) {
	if p.prov.Predicate.Metadata == nil {
		return nil, nil
	}
	return p.prov.Predicate.Metadata.BuildStartedOn, nil
}

// GetBuildFinishTime implements Provenance.GetBuildFinishTime.
func (p *GenericProvenanceV02) GetBuildFinishTime() (*time.Time, error) {
	if p.prov.Predicate.Metadata == nil {
		return nil, nil
	}
	return p.prov.Predicate.Metadata.BuildFinishedOn, nil
}

// GetNumberResolvedDependencies implements Provenance.GetNumberResolvedDependencies.
func (p *GenericProvenanceV02) GetNumberResolvedDependencies() (int, error) {
	return len(p.prov.Predicate.Materials), nil
}

// GetSystemParameters implements Provenance.GetSystemParameters.
func (p *GenericProvenanceV02) GetSystemParameters() (map[string]any, error) {
	environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}
	return environment, nil
}
