package verification

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/mod/semver"
)

var (
	trustedBuilderRepository = "slsa-framework/slsa-github-generator"
	e2eTestRepository        = "slsa-framework/example-package"
	certOidcIssuer           = "https://token.actions.githubusercontent.com"
)

var trustedReusableWorkflows = map[string]bool{
	trustedBuilderRepository + "/.github/workflows/generator_generic_slsa3.yml": true,
	trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml":        true,
}

// VerifyWorkflowIdentity verifies the signing certificate information
func VerifyWorkflowIdentity(id *WorkflowIdentity, source string) error {
	// cert URI path is /org/repo/path/to/workflow@ref
	workflowPath := strings.SplitN(id.JobWobWorkflowRef, "@", 2)
	if len(workflowPath) < 2 {
		return fmt.Errorf("%w: %s", errorMalformedWorkflowURI, id.JobWobWorkflowRef)
	}

	// Trusted workflow verification by name.
	reusableWorkflowName := strings.Trim(workflowPath[0], "/")
	if _, ok := trustedReusableWorkflows[reusableWorkflowName]; !ok {
		return fmt.Errorf("%w: %s", ErrorUntrustedReusableWorkflow, reusableWorkflowName)
	}

	// Verify the ref.
	if err := verifyTrustedBuilderRef(id, strings.Trim(workflowPath[1], "/")); err != nil {
		return err
	}

	// Issuer verification.
	if !strings.EqualFold(id.Issuer, certOidcIssuer) {
		return fmt.Errorf("untrusted token issuer: %s", id.Issuer)
	}

	// The caller repository in the x509 extension is not fully qualified. It only contains
	// {org}/{repository}.
	expectedSource := strings.TrimPrefix(source, "github.com/")
	if !strings.EqualFold(id.CallerRepository, expectedSource) {
		return fmt.Errorf("%w: expected source '%s', got '%s'", ErrorMismatchRepository,
			expectedSource, id.CallerRepository)
	}

	return nil
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
		return fmt.Errorf("%w: %s: not of the form 'refs/tags/name'", errorInvalidRef, ref)
	}

	// Valid semver of the form vX.Y.Z with no metadata.
	pin := strings.TrimPrefix(ref, "refs/tags/")
	if !(semver.IsValid(pin) &&
		len(strings.Split(pin, ".")) == 3 &&
		semver.Prerelease(pin) == "" &&
		semver.Build(pin) == "") {
		return fmt.Errorf("%w: %s: not of the form vX.Y.Z", errorInvalidRef, pin)
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
