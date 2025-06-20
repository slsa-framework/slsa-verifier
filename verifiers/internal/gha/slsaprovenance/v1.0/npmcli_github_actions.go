package v1

import (
	"fmt"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

// NpmCLIGithubActionsBuildType is the build type for the npm-cli GitHub Actions builder.
type NpmCLIGithubActionsProvenance struct {
	*provenanceV1
}

// TriggerURI implements Provenance.TriggerURI.
func (p *NpmCLIGithubActionsProvenance) TriggerURI() (string, error) {
	externalParams, err := p.getExternalParameters()
	if err != nil {
		return "", err
	}
	workflow, ok := externalParams["workflow"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidFormat, "workflow parameters")
	}
	repository, ok := workflow["repository"].(string)
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidFormat, "workflow parameters: repository")
	}
	ref, ok := workflow["ref"].(string)
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidFormat, "workflow parameters: ref")
	}
	uri := fmt.Sprintf("git+%s@%s", repository, ref)
	return uri, nil
}
