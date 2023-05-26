package v02

import (
	"fmt"
	"strings"
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
)

// byobBuildType is the base build type for BYOB delegated builders.
var byobBuildType = "https://github.com/slsa-framework/slsa-github-generator/delegator-generic@v0"

// BYOBProvenanceV02 is SLSA v0.2 provenance for the slsa-github-generator BYOB build type.
type BYOBProvenanceV02 struct {
	prov *intotoAttestation
}

// Predicate implements ProvenanceV02.Predicate
func (p *BYOBProvenanceV02) Predicate() slsa02.ProvenancePredicate {
	return p.prov.Predicate
}

// BuilderID implements Provenance.BuilderID.
func (p *BYOBProvenanceV02) BuilderID() (string, error) {
	return p.prov.Predicate.Builder.ID, nil
}

// SourceURI implements Provenance.SourceURI.
func (p *BYOBProvenanceV02) SourceURI() (string, error) {
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
func (p *BYOBProvenanceV02) TriggerURI() (string, error) {
	uri := p.prov.Predicate.Invocation.ConfigSource.URI
	if uri == "" {
		return "", fmt.Errorf("%w: empty uri", serrors.ErrorMalformedURI)
	}
	return uri, nil
}

// Subjects implements Provenance.Subjects.
func (p *BYOBProvenanceV02) Subjects() ([]intoto.Subject, error) {
	subj := p.prov.Subject
	if len(subj) == 0 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}
	return subj, nil
}

// GetBranch implements Provenance.GetBranch.
func (p *BYOBProvenanceV02) GetBranch() (string, error) {
	// Returns the branch from the source materials.
	sourceURI, err := p.SourceURI()
	if err != nil {
		return "", err
	}

	parts := strings.Split(sourceURI, "@")
	if len(parts) > 1 && strings.HasPrefix(parts[1], "refs/heads") {
		return parts[1], nil
	}

	return "", nil
}

// GetTag implements Provenance.GetTag.
func (p *BYOBProvenanceV02) GetTag() (string, error) {
	// Returns the tag from the source materials.
	sourceURI, err := p.SourceURI()
	if err != nil {
		return "", err
	}

	parts := strings.Split(sourceURI, "@")
	if len(parts) > 1 && strings.HasPrefix(parts[1], "refs/tags") {
		return parts[1], nil
	}

	return "", nil
}

// GetWorkflowInputs implements Provenance.GetWorkflowInputs.
func (p *BYOBProvenanceV02) GetWorkflowInputs() (map[string]interface{}, error) {
	// Verify it's a workflow_dispatch trigger.
	environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	return common.GetWorkflowInputs(environment, common.ProvenanceV02Type)
}

// GetBuildTriggerPath implements Provenance.GetBuildTriggerPath.
func (p *BYOBProvenanceV02) GetBuildTriggerPath() (string, error) {
	return p.prov.Predicate.Invocation.ConfigSource.EntryPoint, nil
}

// GetBuildInvocationID implements Provenance.GetBuildInvocationID.
func (p *BYOBProvenanceV02) GetBuildInvocationID() (string, error) {
	if p.prov.Predicate.Metadata == nil {
		return "", nil
	}
	return p.prov.Predicate.Metadata.BuildInvocationID, nil
}

// GetBuildStartTime implements Provenance.GetBuildStartTime.
func (p *BYOBProvenanceV02) GetBuildStartTime() (*time.Time, error) {
	if p.prov.Predicate.Metadata == nil {
		return nil, nil
	}
	return p.prov.Predicate.Metadata.BuildStartedOn, nil
}

// GetBuildFinishTime implements Provenance.GetBuildFinishTime.
func (p *BYOBProvenanceV02) GetBuildFinishTime() (*time.Time, error) {
	if p.prov.Predicate.Metadata == nil {
		return nil, nil
	}
	return p.prov.Predicate.Metadata.BuildFinishedOn, nil
}

// GetNumberResolvedDependencies implements Provenance.GetNumberResolvedDependencies.
func (p *BYOBProvenanceV02) GetNumberResolvedDependencies() (int, error) {
	return len(p.prov.Predicate.Materials), nil
}

// GetSystemParameters implements Provenance.GetSystemParameters.
func (p *BYOBProvenanceV02) GetSystemParameters() (map[string]any, error) {
	environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}
	return environment, nil
}
