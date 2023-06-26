package v02

import (
	"fmt"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// byobProvenance is SLSA v0.2 provenance created by a BYOB builder.
type byobProvenance struct {
	*provenanceV02
}

func newBYOBProvenance(att *Attestation) *byobProvenance {
	return &byobProvenance{
		provenanceV02: &provenanceV02{
			prov:     att,
			upperEnv: true,
		},
	}
}

// GetBranch implements Provenance.GetBranch.
func (p *byobProvenance) GetBranch() (string, error) {
	sourceURI, err := p.SourceURI()
	if err != nil {
		// GetBranch gets the branch from the invocation parameters.
		environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
		}

		return common.GetBranch(environment, true)
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
		sysParams, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
		}
		return common.GetBranch(sysParams, true)
	default:
		return "", fmt.Errorf("%w: unknown ref type %q for ref %q",
			serrors.ErrorInvalidDssePayload, refType, ref)
	}
}

// GetTag implements Provenance.GetTag.
func (p *byobProvenance) GetTag() (string, error) {
	sourceURI, err := p.SourceURI()
	if err != nil {
		environment, ok := p.prov.Predicate.Invocation.Environment.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "parameters type")
		}

		return common.GetTag(environment, true)
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
