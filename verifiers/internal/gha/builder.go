package gha

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net/url"
	"strings"

	fulcio "github.com/sigstore/fulcio/pkg/certificate"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

var (
	trustedBuilderRepository = "slsa-framework/slsa-github-generator"
	e2eTestRepository        = "slsa-framework/example-package"
	certOidcIssuer           = "https://token.actions.githubusercontent.com"
	githubCom                = "github.com/"
	httpsGithubCom           = "https://" + githubCom
	// This is used in cosign's CheckOpts for validating the certificate. We
	// do specific builder verification after this.
	certSubjectRegexp = httpsGithubCom + "*"
)

var defaultArtifactTrustedReusableWorkflows = map[string]bool{
	common.GenericGeneratorBuilderID: true,
	common.GoBuilderID:               true,
	common.ContainerBasedBuilderID:   true,
}

var defaultContainerTrustedReusableWorkflows = map[string]bool{
	common.ContainerGeneratorBuilderID: true,
}

var defaultBYOBReusableWorkflows = map[string]bool{
	common.GenericDelegatorBuilderID:         true,
	common.GenericLowPermsDelegatorBuilderID: true,
}

// VerifyCertficateSourceRepository verifies the source repository.
func VerifyCertficateSourceRepository(id *WorkflowIdentity,
	sourceRepo string,
) error {
	// The caller repository in the x509 extension is not fully qualified. It only contains
	// {org}/{repository}.
	expectedSource := strings.TrimPrefix(sourceRepo, "git+https://")
	expectedSource = strings.TrimPrefix(expectedSource, githubCom)
	if id.SourceRepository != expectedSource {
		return fmt.Errorf("%w: expected source '%s', got '%s'", serrors.ErrorMismatchSource,
			expectedSource, id.SourceRepository)
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
) (*utils.TrustedBuilderID, bool, error) {
	// Issuer verification.
	// NOTE: this is necessary before we do any further verification.
	if id.Issuer != certOidcIssuer {
		return nil, false, fmt.Errorf("%w: %q", serrors.ErrorInvalidOIDCIssuer, id.Issuer)
	}

	// cert URI is https://github.com/org/repo/path/to/workflow@ref
	// Remove '@' from Path
	workflowID := id.SubjectWorkflowName()
	workflowTag := id.SubjectWorkflowRef()

	fmt.Println("workflowID", workflowID)
	fmt.Println("workflowTag", workflowTag)

	if workflowID == "" || workflowTag == "" {
		return nil, false, fmt.Errorf("%w: workflow uri: %q", serrors.ErrorMalformedURI, id.SubjectWorkflow.String())
	}

	// Verify trusted workflow.
	builderID, byob, err := verifyTrustedBuilderID(workflowID, workflowTag,
		builderOpts.ExpectedID, defaultBuilders)
	if err != nil {
		return nil, byob, err
	}

	// Verify the ref is a full semantic version tag.
	if err := verifyTrustedBuilderRef(id, workflowTag); err != nil {
		return nil, byob, err
	}

	return builderID, byob, nil
}

// Verifies the builder ID at path against an expected builderID.
// If an expected builderID is not provided, uses the defaultBuilders.
func verifyTrustedBuilderID(certBuilderID, certTag string, expectedBuilderID *string, defaultTrustedBuilders map[string]bool) (*utils.TrustedBuilderID, bool, error) {
	var trustedBuilderID *utils.TrustedBuilderID
	var err error
	// WARNING: we don't validate the tag here, because we need to allow
	// refs/heads/main for e2e tests. See verifyTrustedBuilderRef().
	// No builder ID provided by user: use the default trusted workflows.
	if expectedBuilderID == nil || *expectedBuilderID == "" {
		if _, ok := defaultTrustedBuilders[certBuilderID]; !ok {
			return nil, false, fmt.Errorf("%w: %s with builderID provided: %t", serrors.ErrorUntrustedReusableWorkflow, certBuilderID, expectedBuilderID != nil)
		}
		// Construct the builderID using the certificate's builder's name and tag.
		trustedBuilderID, err = utils.TrustedBuilderIDNew(certBuilderID+"@"+certTag, true)
		if err != nil {
			return nil, false, err
		}
	} else {
		// Verify the builderID.
		// We only accept IDs on github.com.
		trustedBuilderID, err = utils.TrustedBuilderIDNew(certBuilderID+"@"+certTag, true)
		if err != nil {
			return nil, false, err
		}

		// Check if:
		// - the builder in the cert is a BYOB builder
		// - the caller trusts the BYOB builder
		// If both are true, we don't match the user-provided builder ID
		// against the certificate. Instead that will be done by the caller.
		if isTrustedDelegatorBuilder(trustedBuilderID, defaultTrustedBuilders) {
			return trustedBuilderID, true, nil
		}

		// Not a BYOB builder. BuilderID provided by user should match the certificate.
		// Note: the certificate builderID has the form `name@refs/tags/v1.2.3`,
		// so we pass `allowRef = true`.
		if err := trustedBuilderID.MatchesLoose(*expectedBuilderID, true); err != nil {
			return nil, false, fmt.Errorf("%w: %v", serrors.ErrorUntrustedReusableWorkflow, err)
		}
	}

	return trustedBuilderID, false, nil
}

func isTrustedDelegatorBuilder(certBuilder *utils.TrustedBuilderID, trustedBuilders map[string]bool) bool {
	for byobBuilder := range defaultBYOBReusableWorkflows {
		// Check that the certificate builder is a BYOB workflow.
		if err := certBuilder.MatchesLoose(httpsGithubCom+byobBuilder, true); err == nil {
			// We found a delegator workflow that matches the certificate identity.
			// Check that the BYOB builder is trusted by the caller.
			if _, ok := trustedBuilders[byobBuilder]; !ok {
				return false
			}
			return true
		}
	}
	return false
}

// Only allow `@refs/heads/main` for the builder and the e2e tests that need to work at HEAD.
// This lets us use the pre-build builder binary generated during release (release happen at main).
// For other projects, we only allow semantic versions that map to a release.
func verifyTrustedBuilderRef(id *WorkflowIdentity, ref string) error {
	if (id.SourceRepository == trustedBuilderRepository ||
		id.SourceRepository == e2eTestRepository) &&
		options.TestingEnabled() {
		// Allow verification on the main branch to support e2e tests.
		if ref == "refs/heads/main" {
			return nil
		}

		return utils.IsValidBuilderTag(ref, true)
	}

	return utils.IsValidBuilderTag(ref, false)
}

func getExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier, encoded bool) (string, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oid) {
			continue
		}
		if !encoded {
			return string(ext.Value), nil
		}

		// Decode first.
		var decoded string
		rest, err := asn1.Unmarshal(ext.Value, &decoded)
		if err != nil {
			return "", fmt.Errorf("%w", err)
		}
		if len(rest) != 0 {
			return "", fmt.Errorf("decoding has rest for oid %v", oid)
		}
		return decoded, nil
	}
	return "", nil
}

type Hosted int

const (
	HostedSelf Hosted = iota
	HostedGitHub
)

// WorkflowIdentity is a identity captured from a Fulcio certificate.
// See https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md.
type WorkflowIdentity struct {
	// The source repository
	SourceRepository string
	// The commit SHA where the workflow was triggered.
	SourceSha1 string
	// Ref of the source.
	SourceRef *string
	// ID of the source repository.
	SourceID *string
	//  Source owner ID of repository.
	SourceOwnerID *string

	// Workflow path OIDC subject - ref of reuseable workflow or trigger workflow.
	SubjectWorkflow *url.URL
	// Subject commit sha1.
	SubjectSha1 *string
	// Hosted status of the subject.
	SubjectHosted *Hosted

	// BuildTrigger
	BuildTrigger string
	// Build config path, i.e. the trigger workflow.
	BuildConfigPath *string

	// Run ID
	RunID *string
	// Issuer
	Issuer string
}

// SubjectWorkflowName returns the subject workflow without the git ref.
func (id *WorkflowIdentity) SubjectWorkflowName() string {
	withoutRef, err := url.Parse(id.SubjectWorkflow.String())
	if err != nil {
		// This should never happen.
		panic(err)
	}
	withoutRef.Path = id.SubjectWorkflowPath()
	return withoutRef.String()
}

// SubjectWorkflowPath returns the subject workflow without the server url.
func (id *WorkflowIdentity) SubjectWorkflowPath() string {
	parts := strings.SplitN(id.SubjectWorkflow.Path, "@", 2)
	return parts[0]
}

// SubjectWorkflowRef returns the ref for the subject workflow.
func (id *WorkflowIdentity) SubjectWorkflowRef() string {
	parts := strings.SplitN(id.SubjectWorkflow.Path, "@", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func getHosted(cert *x509.Certificate) (*Hosted, error) {
	runnerEnv, err := getExtension(cert, fulcio.OIDRunnerEnvironment, true)
	if err != nil {
		return nil, err
	}
	if runnerEnv == "github-hosted" {
		r := HostedGitHub
		return &r, nil
	}
	if runnerEnv == "self-hosted" {
		r := HostedSelf
		return &r, nil
	}
	return nil, nil
}

func validateClaimsEqual(deprecated, existing string) error {
	if deprecated != "" && existing != "" && deprecated != existing {
		return fmt.Errorf("%w: '%v' != '%v'", serrors.ErrorInvalidFormat, deprecated, existing)
	}
	if deprecated == "" && existing == "" {
		return fmt.Errorf("%w: claims are empty", serrors.ErrorInvalidFormat)
	}
	return nil
}

func getAndValidateEqualClaims(cert *x509.Certificate, deprecatedOid, oid asn1.ObjectIdentifier) (string, error) {
	deprecatedValue, err := getExtension(cert, deprecatedOid, false)
	if err != nil {
		return "", err
	}
	value, err := getExtension(cert, oid, true)
	if err != nil {
		return "", err
	}
	if err := validateClaimsEqual(deprecatedValue, value); err != nil {
		return "", err
	}
	// New certificates.
	if value != "" {
		return value, nil
	}
	// Old certificates.
	if deprecatedValue != "" {
		return deprecatedValue, nil
	}
	// Both values are empty.
	return "", fmt.Errorf("%w: empty fields %v and %v", serrors.ErrorInvalidCertificate,
		deprecatedOid, oid)
}

// GetWorkflowFromCertificate gets the workflow identity from the Fulcio authenticated content.
// See https://github.com/sigstore/fulcio/blob/e763d76e3f7786b52db4b27ab87dc446da24895a/pkg/certificate/extensions.go.
// https://github.com/golangci/golangci-lint/issues/741#issuecomment-784171870.
//
//nolint:staticcheck // we want to disable SA1019 only to use deprecated methods but there is a bug in golangci-lint.
func GetWorkflowInfoFromCertificate(cert *x509.Certificate) (*WorkflowIdentity, error) {
	if len(cert.URIs) == 0 {
		return nil, fmt.Errorf("%w: missing URI information from certificate", serrors.ErrorInvalidFormat)
	}

	// 1.3.6.1.4.1.57264.1.2: DEPRECATED.
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726412--github-workflow-BuildTrigger-deprecated
	// 1.3.6.1.4.1.57264.1.20 | Build Trigger
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264120--build-trigger
	buildTrigger, err := getAndValidateEqualClaims(cert, fulcio.OIDGitHubWorkflowTrigger, fulcio.OIDBuildTrigger)
	if err != nil {
		return nil, err
	}

	// 1.3.6.1.4.1.57264.1.3: DEPRECATED.
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726413--github-workflow-sha-deprecated
	// 1.3.6.1.4.1.57264.1.13 | Source Repository Digest
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264113--source-repository-digest
	sourceSha1, err := getAndValidateEqualClaims(cert, fulcio.OIDGitHubWorkflowSHA, fulcio.OIDSourceRepositoryDigest)
	if err != nil {
		return nil, err
	}
	// 1.3.6.1.4.1.57264.1.19 | Build Config Digest
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264119--build-config-digest
	buildConfigSha1, err := getExtension(cert, fulcio.OIDBuildConfigDigest, true)
	if err != nil {
		return nil, err
	}
	if err := validateClaimsEqual(sourceSha1, buildConfigSha1); err != nil {
		return nil, err
	}

	// IssuerV1: 1.3.6.1.4.1.57264.1.1
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726411--issuer
	// IssuerV2: 1.3.6.1.4.1.57264.1.8
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726418--issuer-v2
	issuer, err := getAndValidateEqualClaims(cert, fulcio.OIDIssuer, fulcio.OIDIssuerV2)
	if err != nil {
		return nil, err
	}

	// 1.3.6.1.4.1.57264.1.5: DEPRECATED.
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726415--github-workflow-repository-deprecated
	deprecatedSourceRepository, err := getExtension(cert, fulcio.OIDGitHubWorkflowRepository, false)
	if err != nil {
		return nil, err
	}
	// 1.3.6.1.4.1.57264.1.12 | Source Repository URI
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264112--source-repository-uri
	sourceURI, err := getExtension(cert, fulcio.OIDSourceRepositoryURI, true)
	if err != nil {
		return nil, err
	}
	if deprecatedSourceRepository != "" && sourceURI != "" &&
		"https://github.com/"+deprecatedSourceRepository != sourceURI {
		return nil, fmt.Errorf("%w: '%v' != '%v'",
			serrors.ErrorInvalidFormat, "https://github.com/"+deprecatedSourceRepository, sourceURI)
	}
	sourceRepository := strings.TrimPrefix(sourceURI, "https://github.com/")
	// Handle old certifcates.
	if sourceRepository == "" {
		sourceRepository = deprecatedSourceRepository
	}

	// 1.3.6.1.4.1.57264.1.10 | Build Signer Digest
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264110--build-signer-digest
	subjectSha1, err := getExtension(cert, fulcio.OIDBuildSignerDigest, true)
	if err != nil {
		return nil, err
	}

	// 1.3.6.1.4.1.57264.1.11 | Runner Environment
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264111--runner-environment
	subjectHosted, err := getHosted(cert)
	if err != nil {
		return nil, err
	}

	// 1.3.6.1.4.1.57264.1.14 | Source Repository Ref
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264114--source-repository-ref
	sourceRef, err := getExtension(cert, fulcio.OIDSourceRepositoryRef, true)
	if err != nil {
		return nil, err
	}

	// 1.3.6.1.4.1.57264.1.15 | Source Repository Identifier
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264115--source-repository-identifier
	sourceID, err := getExtension(cert, fulcio.OIDSourceRepositoryIdentifier, true)
	if err != nil {
		return nil, err
	}

	// 1.3.6.1.4.1.57264.1.17 | Source Repository Owner Identifier
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264117--source-repository-owner-identifier
	sourceOwnerID, err := getExtension(cert, fulcio.OIDSourceRepositoryOwnerIdentifier, true)
	if err != nil {
		return nil, err
	}

	// 1.3.6.1.4.1.57264.1.18 | Build Config URI
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264118--build-config-uri
	var buildConfigPath string
	buildConfigURI, err := getExtension(cert, fulcio.OIDBuildConfigURI, true)
	if err != nil {
		return nil, err
	}
	if buildConfigURI != "" {
		parts := strings.Split(buildConfigURI, "@")
		if len(parts) != 2 {
			return nil, fmt.Errorf("%w: %v",
				serrors.ErrorInvalidFormat, buildConfigURI)
		}
		prefix := fmt.Sprintf("https://github.com/%v/", sourceRepository)
		if !strings.HasPrefix(parts[0], prefix) {
			return nil, fmt.Errorf("%w: prefix: %v",
				serrors.ErrorInvalidFormat, parts[0])
		}
		buildConfigPath = strings.TrimPrefix(parts[0], prefix)
	}

	// 1.3.6.1.4.1.57264.1.21 | Run Invocation URI
	// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264121--run-invocation-uri
	runURI, err := getExtension(cert, fulcio.OIDRunInvocationURI, true)
	if err != nil {
		return nil, err
	}
	runID := strings.TrimPrefix(runURI, fmt.Sprintf("https://github.com/%s/actions/runs/", sourceRepository))

	// Subject path.
	if !strings.HasPrefix(cert.URIs[0].Path, "/") {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidFormat, cert.URIs[0].Path)
	}
	subjectWorkflow := cert.URIs[0]

	var pSubjectSha1, pSourceID, pSourceRef, pSourceOwnerID, pBuildConfigPath, pRunID *string
	if subjectSha1 != "" {
		pSubjectSha1 = &subjectSha1
	}
	if sourceID != "" {
		pSourceID = &sourceID
	}
	if sourceRef != "" {
		pSourceRef = &sourceRef
	}
	if sourceOwnerID != "" {
		pSourceOwnerID = &sourceOwnerID
	}
	if buildConfigPath != "" {
		pBuildConfigPath = &buildConfigPath
	}
	if runID != "" {
		pRunID = &runID
	}

	return &WorkflowIdentity{
		// Issuer.
		Issuer: issuer,
		// Subject
		SubjectWorkflow: subjectWorkflow,
		SubjectSha1:     pSubjectSha1,
		SubjectHosted:   subjectHosted,
		// Source.
		SourceRepository: sourceRepository,
		SourceSha1:       sourceSha1,
		SourceRef:        pSourceRef,
		SourceID:         pSourceID,
		SourceOwnerID:    pSourceOwnerID,
		// Build.
		BuildTrigger:    buildTrigger,
		BuildConfigPath: pBuildConfigPath,
		// Other.
		RunID: pRunID,
	}, nil
}
