package gha

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

var (
	trustedBuilderRepository = "slsa-framework/slsa-github-generator"
	e2eTestRepository        = "slsa-framework/example-package"
	certOidcIssuer           = "https://token.actions.githubusercontent.com"
	// This is used in cosign's CheckOpts for validating the certificate. We
	// do specific builder verification after this.
	certSubjectRegexp = "https://github.com/*"
)

var defaultArtifactTrustedReusableWorkflows = map[string]bool{
	trustedBuilderRepository + "/.github/workflows/generator_generic_slsa3.yml":    true,
	trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml":           true,
	trustedBuilderRepository + "/.github/workflows/builder_docker-based_slsa3.yml": true,
}

var defaultContainerTrustedReusableWorkflows = map[string]bool{
	trustedBuilderRepository + "/.github/workflows/generator_container_slsa3.yml": true,
}

var defaultBYOBReusableWorkflows = map[string]bool{
	trustedBuilderRepository + "/.github/workflows/delegator_generic_slsa3.yml": true,
}

// VerifyCertficateSourceRepository verifies the source repository.
func VerifyCertficateSourceRepository(id *WorkflowIdentity,
	sourceRepo string,
) error {
	// The caller repository in the x509 extension is not fully qualified. It only contains
	// {org}/{repository}.
	expectedSource := strings.TrimPrefix(sourceRepo, "git+https://")
	expectedSource = strings.TrimPrefix(expectedSource, "github.com/")
	if id.CallerRepository != expectedSource {
		return fmt.Errorf("%w: expected source '%s', got '%s'", serrors.ErrorMismatchSource,
			expectedSource, id.CallerRepository)
	}
	return nil
}

// VerifyBuilderIdentity verifies the signing certificate information.
// Builder IDs are verified against an expected builder ID provided in the
// builerOpts, or against the set of defaultBuilders provided. The identiy
// in the certificate corresponds to a GitHub workflow's path.
func VerifyBuilderIdentity(id *WorkflowIdentity,
	builderOpts *options.BuilderOpts,
	defaultBuilders map[string]bool,
) (*utils.TrustedBuilderID, error) {
	// Issuer verification.
	// NOTE: this is necessary before we do any further verification.
	if id.Issuer != certOidcIssuer {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidOIDCIssuer, id.Issuer)
	}

	// cert URI path is /org/repo/path/to/workflow@ref
	workflowPath := strings.SplitN(id.JobWobWorkflowRef, "@", 2)
	if len(workflowPath) < 2 {
		return nil, fmt.Errorf("%w: workflow uri: %s", serrors.ErrorMalformedURI, id.JobWobWorkflowRef)
	}

	// Verify trusted workflow.
	reusableWorkflowPath := strings.Trim(workflowPath[0], "/")
	reusableWorkflowTag := strings.Trim(workflowPath[1], "/")
	builderID, err := verifyTrustedBuilderID(reusableWorkflowPath, reusableWorkflowTag,
		builderOpts.ExpectedID, defaultBuilders)
	if err != nil {
		return nil, err
	}

	// Verify the ref is a full semantic version tag.
	if err := verifyTrustedBuilderRef(id, reusableWorkflowTag); err != nil {
		return nil, err
	}

	return builderID, nil
}

// Verifies the builder ID at path against an expected builderID.
// If an expected builderID is not provided, uses the defaultBuilders.
func verifyTrustedBuilderID(certPath, certTag string, expectedBuilderID *string, defaultBuilders map[string]bool) (*utils.TrustedBuilderID, error) {
	var trustedBuilderID *utils.TrustedBuilderID
	var err error
	certBuilderName := "https://github.com/" + certPath
	// WARNING: we don't validate the tag here, because we need to allow
	// refs/heads/main for e2e tests. See verifyTrustedBuilderRef().
	// No builder ID provided by user: use the default trusted workflows.
	if expectedBuilderID == nil || *expectedBuilderID == "" {
		if _, ok := defaultBuilders[certPath]; !ok {
			return nil, fmt.Errorf("%w: %s got %t", serrors.ErrorUntrustedReusableWorkflow, certPath, expectedBuilderID == nil)
		}
		// Construct the builderID using the certificate's builder's name and tag.
		trustedBuilderID, err = utils.TrustedBuilderIDNew(certBuilderName + "@" + certTag)
		if err != nil {
			return nil, err
		}
	} else {
		// Verify the builderID.
		// We only accept IDs on github.com.
		trustedBuilderID, err = utils.TrustedBuilderIDNew(certBuilderName + "@" + certTag)
		if err != nil {
			return nil, err
		}

		// BuilderID provided by user should match the certificate.
		// Note: the certificate builderID has the form `name@refs/tags/v1.2.3`,
		// so we pass `allowRef = true`.
		if err := trustedBuilderID.Matches(*expectedBuilderID, true); err != nil {
			return nil, fmt.Errorf("%w: %v", serrors.ErrorUntrustedReusableWorkflow, err)
		}
	}

	return trustedBuilderID, nil
}

// Only allow `@refs/heads/main` for the builder and the e2e tests that need to work at HEAD.
// This lets us use the pre-build builder binary generated during release (release happen at main).
// For other projects, we only allow semantic versions that map to a release.
func verifyTrustedBuilderRef(id *WorkflowIdentity, ref string) error {
	if (id.CallerRepository == trustedBuilderRepository ||
		id.CallerRepository == e2eTestRepository) &&
		options.TestingEnabled() {
		// Allow verification on the main branch to support e2e tests.
		if ref == "refs/heads/main" {
			return nil
		}

		// Extract the tag.
		pin, err := utils.TagFromGitHubRef(ref)
		if err != nil {
			return err
		}

		// Tags on trusted repositories should be a valid semver with version
		// core including all three parts and no build identifier.
		versionCore := strings.Split(pin, "-")[0]
		if !semver.IsValid(pin) ||
			len(strings.Split(versionCore, ".")) != 3 ||
			semver.Build(pin) != "" {
			return fmt.Errorf("%w: %s: version tag not valid", serrors.ErrorInvalidRef, pin)
		}

		return nil
	}

	// Extract the pin.
	pin, err := utils.TagFromGitHubRef(ref)
	if err != nil {
		return err
	}

	// Valid semver of the form vX.Y.Z with no metadata.
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
