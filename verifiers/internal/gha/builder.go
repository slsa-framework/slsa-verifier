package gha

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/slsa-framework/slsa-verifier/options"
)

var (
	trustedBuilderRepository = "slsa-framework/slsa-github-generator"
	e2eTestRepository        = "slsa-framework/example-package"
	certOidcIssuer           = "https://token.actions.githubusercontent.com"
)

var defaultArtifactTrustedReusableWorkflows = map[string]bool{
	trustedBuilderRepository + "/.github/workflows/generator_generic_slsa3.yml": true,
	trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml":        true,
}

var defaultContainerTrustedReusableWorkflows = map[string]bool{
	trustedBuilderRepository + "/.github/workflows/generator_container_slsa3.yml": true,
}

// VerifyWorkflowIdentity verifies the signing certificate information
// Builder IDs are verified against an expected builder ID provided in the
// builerOpts, or against the set of defaultBuilders provided.
func VerifyWorkflowIdentity(id *WorkflowIdentity,
	builderOpts *options.BuilderOpts, source string,
	defaultBuilders map[string]bool,
) (string, error) {
	// cert URI path is /org/repo/path/to/workflow@ref
	workflowPath := strings.SplitN(id.JobWobWorkflowRef, "@", 2)
	if len(workflowPath) < 2 {
		return "", fmt.Errorf("%w: workflow uri: %s", serrors.ErrorMalformedURI, id.JobWobWorkflowRef)
	}

	// Trusted workflow verification by name.
	reusableWorkflowPath := strings.Trim(workflowPath[0], "/")
	builderID, err := verifyTrustedBuilderID(reusableWorkflowPath,
		builderOpts.ExpectedID, defaultBuilders)
	if err != nil {
		return "", err
	}

	// Verify the ref.
	if err := verifyTrustedBuilderRef(id, strings.Trim(workflowPath[1], "/")); err != nil {
		return "", err
	}

	// Issuer verification.
	if !strings.EqualFold(id.Issuer, certOidcIssuer) {
		return "", fmt.Errorf("untrusted token issuer: %s", id.Issuer)
	}

	// The caller repository in the x509 extension is not fully qualified. It only contains
	// {org}/{repository}.
	expectedSource := strings.TrimPrefix(source, "git+https://")
	expectedSource = strings.TrimPrefix(expectedSource, "github.com/")
	if !strings.EqualFold(id.CallerRepository, expectedSource) {
		return "", fmt.Errorf("%w: expected source '%s', got '%s'", serrors.ErrorMismatchSource,
			expectedSource, id.CallerRepository)
	}

	// Return the builder and its tag.
	return builderID, nil
}

// Verifies the builder ID at path against an expected builderID.
// If an expected builderID is not provided, uses the defaultBuilders.
func verifyTrustedBuilderID(path string, builderID *string, defaultBuilders map[string]bool) (string, error) {
	// No builder ID provided by user: use the default trusted workflows.
	if builderID == nil || *builderID == "" {
		if _, ok := defaultBuilders[path]; !ok {
			return "", fmt.Errorf("%w: %s got %t", serrors.ErrorUntrustedReusableWorkflow, path, builderID == nil)
		}
	} else {
		// Verify the builderID.
		// We only accept IDs on github.com.
		url := "https://github.com/" + path
		if url != *builderID {
			return "", fmt.Errorf("%w: expected buildID '%s', got '%s'", serrors.ErrorUntrustedReusableWorkflow,
				*builderID, url)
		}
	}

	return "https://github.com/" + path, nil
}

// Only allow `@refs/heads/main` for the builder and the e2e tests that need to work at HEAD.
// This lets us use the pre-build builder binary generated during release (release happen at main).
// For other projects, we only allow semantic versions that map to a release.
func verifyTrustedBuilderRef(id *WorkflowIdentity, ref string) error {
	if (id.CallerRepository == trustedBuilderRepository ||
		id.CallerRepository == e2eTestRepository) &&
		strings.EqualFold("refs/heads/main", ref) {
		return nil
	}

	if !strings.HasPrefix(ref, "refs/tags/") {
		return fmt.Errorf("%w: %s: not of the form 'refs/tags/name'", serrors.ErrorInvalidRef, ref)
	}

	// Valid semver of the form vX.Y.Z with no metadata.
	pin := strings.TrimPrefix(ref, "refs/tags/")
	if !(semver.IsValid(pin) &&
		len(strings.Split(pin, ".")) == 3 &&
		semver.Prerelease(pin) == "" &&
		semver.Build(pin) == "") {
		return fmt.Errorf("%w: %s: not of the form vX.Y.Z", serrors.ErrorInvalidRef, pin)
	}
	return nil
}

func getExtension(cert *x509.Certificate, oid string) string {
	for _, ext := range cert.Extensions {
		if strings.Contains(ext.Id.String(), oid) {
			return string(ext.Value)
		}
	}
	return ""
}

type WorkflowIdentity struct {
	// The caller repository
	CallerRepository string `json:"caller"`
	// The commit SHA where the workflow was triggered
	CallerHash string `json:"commit"`
	// Current workflow (reuseable workflow) ref
	JobWobWorkflowRef string `json:"job_workflow_ref"`
	// Trigger
	Trigger string `json:"trigger"`
	// Issuer
	Issuer string `json:"issuer"`
}

// GetWorkflowFromCertificate gets the workflow identity from the Fulcio authenticated content.
func GetWorkflowInfoFromCertificate(cert *x509.Certificate) (*WorkflowIdentity, error) {
	if len(cert.URIs) == 0 {
		return nil, errors.New("missing URI information from certificate")
	}

	return &WorkflowIdentity{
		CallerRepository:  getExtension(cert, "1.3.6.1.4.1.57264.1.5"),
		Issuer:            getExtension(cert, "1.3.6.1.4.1.57264.1.1"),
		Trigger:           getExtension(cert, "1.3.6.1.4.1.57264.1.2"),
		CallerHash:        getExtension(cert, "1.3.6.1.4.1.57264.1.3"),
		JobWobWorkflowRef: cert.URIs[0].Path,
	}, nil
}
