package v02

import (
	"fmt"
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
)

// provenanceV02 implements basic logic for SLSA v0.2 provenance.
type provenanceV02 struct {
	// upperEnv specifies if environment fields are in uppercase.
	upperEnv bool
	prov     *Attestation
}

// Predicate implements provenanceV02.Predicate.
func (p *provenanceV02) Predicate() slsa02.ProvenancePredicate {
	return p.prov.Predicate
}

// BuilderID implements Provenance.BuilderID.
func (p *provenanceV02) BuilderID() (string, error) {
	return p.prov.Predicate.Builder.ID, nil
}

// SourceURI implements Provenance.SourceURI.
func (p *provenanceV02) SourceURI() (string, error) {
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
func (p *provenanceV02) TriggerURI() (string, error) {
	uri := p.prov.Predicate.Invocation.ConfigSource.URI
	if uri == "" {
		return "", fmt.Errorf("%w: empty uri", serrors.ErrorMalformedURI)
	}
	return uri, nil
}

// Subjects implements Provenance.Subjects.
func (p *provenanceV02) Subjects() ([]intoto.Subject, error) {
	subj := p.prov.Subject
	if len(subj) == 0 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}
	return subj, nil
}

// GetBranch implements Provenance.GetBranch.
func (p *provenanceV02) GetBranch() (string, error) {
	// GetBranch gets the branch from the invocation parameters.
	environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	return common.GetBranch(environment, p.upperEnv)
}

// GetTag implements Provenance.GetTag.
func (p *provenanceV02) GetTag() (string, error) {
	environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	return common.GetTag(environment, p.upperEnv)
}

// GetWorkflowInputs implements Provenance.GetWorkflowInputs.
func (p *provenanceV02) GetWorkflowInputs() (map[string]interface{}, error) {
	// Verify it's a workflow_dispatch trigger.
	environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}

	return common.GetWorkflowInputs(environment, p.upperEnv)
}

// GetBuildTriggerPath implements Provenance.GetBuildTriggerPath.
func (p *provenanceV02) GetBuildTriggerPath() (string, error) {
	return p.prov.Predicate.Invocation.ConfigSource.EntryPoint, nil
}

// GetBuildInvocationID implements Provenance.GetBuildInvocationID.
func (p *provenanceV02) GetBuildInvocationID() (string, error) {
	if p.prov.Predicate.Metadata == nil {
		return "", nil
	}
	return p.prov.Predicate.Metadata.BuildInvocationID, nil
}

// GetBuildStartTime implements Provenance.GetBuildStartTime.
func (p *provenanceV02) GetBuildStartTime() (*time.Time, error) {
	if p.prov.Predicate.Metadata == nil {
		return nil, nil
	}
	return p.prov.Predicate.Metadata.BuildStartedOn, nil
}

// GetBuildFinishTime implements Provenance.GetBuildFinishTime.
func (p *provenanceV02) GetBuildFinishTime() (*time.Time, error) {
	if p.prov.Predicate.Metadata == nil {
		return nil, nil
	}
	return p.prov.Predicate.Metadata.BuildFinishedOn, nil
}

// GetNumberResolvedDependencies implements Provenance.GetNumberResolvedDependencies.
func (p *provenanceV02) GetNumberResolvedDependencies() (int, error) {
	return len(p.prov.Predicate.Materials), nil
}

// GetSystemParameters implements Provenance.GetSystemParameters.
func (p *provenanceV02) GetSystemParameters() (map[string]any, error) {
	environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
	}
	return environment, nil
}
