package v1

import (
	"fmt"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// BYOBBuildType is the base build type for BYOB delegated builders.
var BYOBBuildType = "https://github.com/slsa-framework/slsa-github-generator/delegator-generic@v0"

// BYOBProvenance is SLSA v1.0 provenance for the slsa-github-generator BYOB build type.
type BYOBProvenance struct {
	*provenanceV1
}

// GetBranch implements Provenance.GetBranch.
func (p *BYOBProvenance) GetBranch() (string, error) {
	sourceURI, err := p.SourceURI()
	if err != nil {
		return "", fmt.Errorf("reading source uri: %w", err)
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
	case refNameHeads: // branch.
		// NOTE: We return the full git ref.
		return ref, nil
	case refNameTags:
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
		return "", fmt.Errorf("reading source uri: %w", err)
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
	case refNameHeads: // branch.
		return "", nil
	case refNameTags:
		// NOTE: We return the full git ref.
		return ref, nil
	default:
		return "", fmt.Errorf("%w: unknown ref type %q for ref %q",
			serrors.ErrorInvalidDssePayload, refType, ref)
	}
}
