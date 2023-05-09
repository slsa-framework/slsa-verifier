package gha

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	fulcio "github.com/sigstore/fulcio/pkg/certificate"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
)

func Test_VerifyBuilderIdentity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		workflow  *WorkflowIdentity
		buildOpts *options.BuilderOpts
		builderID string
		defaults  map[string]bool
		err       error
	}{
		{
			name: "invalid job workflow ref",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: "random/workflow/ref",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             "https://token.actions.githubusercontent.com",
			},
			defaults: defaultArtifactTrustedReusableWorkflows,
			err:      serrors.ErrorMalformedURI,
		},
		{
			name: "untrusted job workflow ref",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: "/malicious/slsa-go/.github/workflows/builder.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             "https://token.actions.githubusercontent.com",
			},
			defaults: defaultArtifactTrustedReusableWorkflows,
			err:      serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name: "untrusted job workflow ref for general repos",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/heads/main",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             "https://token.actions.githubusercontent.com",
			},
			defaults: defaultArtifactTrustedReusableWorkflows,
			err:      serrors.ErrorInvalidRef,
		},
		{
			name: "untrusted cert issuer for general repos",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             "https://bad.issuer.com",
			},
			defaults: defaultArtifactTrustedReusableWorkflows,
			err:      serrors.ErrorInvalidOIDCIssuer,
		},
		{
			name: "valid trusted builder without tag",
			workflow: &WorkflowIdentity{
				SourceRepository:   trustedBuilderRepository,
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             "https://token.actions.githubusercontent.com",
			},
			defaults:  defaultArtifactTrustedReusableWorkflows,
			builderID: "https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml",
		},
		{
			name: "valid main ref for e2e test",
			workflow: &WorkflowIdentity{
				SourceRepository:   e2eTestRepository,
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			defaults:  defaultArtifactTrustedReusableWorkflows,
			builderID: "https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml",
		},
		{
			name: "valid main ref for e2e test - match builderID",
			workflow: &WorkflowIdentity{
				SourceRepository:   e2eTestRepository,
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			buildOpts: &options.BuilderOpts{
				ExpectedID: asStringPointer("https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml"),
			},
			defaults:  defaultArtifactTrustedReusableWorkflows,
			builderID: "https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml",
		},
		{
			name: "valid main ref for e2e test - mismatch builderID",
			workflow: &WorkflowIdentity{
				SourceRepository:   e2eTestRepository,
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			buildOpts: &options.BuilderOpts{
				ExpectedID: asStringPointer("some-other-builderID"),
			},
			defaults: defaultArtifactTrustedReusableWorkflows,
			err:      serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name: "valid workflow identity - match builderID",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			buildOpts: &options.BuilderOpts{
				ExpectedID: asStringPointer("https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml"),
			},
			defaults:  defaultArtifactTrustedReusableWorkflows,
			builderID: "https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml",
		},
		{
			name: "valid workflow identity - mismatch builderID",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			buildOpts: &options.BuilderOpts{
				ExpectedID: asStringPointer("some-other-builderID"),
			},
			defaults: defaultArtifactTrustedReusableWorkflows,
			err:      serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name: "invalid workflow identity with prerelease",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3-alpha",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			err:       serrors.ErrorInvalidRef,
			defaults:  defaultArtifactTrustedReusableWorkflows,
			builderID: "https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml",
		},
		{
			name: "invalid workflow identity with build",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3+123",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			defaults: defaultArtifactTrustedReusableWorkflows,
			err:      serrors.ErrorInvalidRef,
		},
		{
			name: "invalid workflow identity with metadata",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3-alpha+123",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			defaults: defaultArtifactTrustedReusableWorkflows,
			err:      serrors.ErrorInvalidRef,
		},
		{
			name: "valid workflow identity with fully qualified source",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			defaults:  defaultArtifactTrustedReusableWorkflows,
			builderID: "https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml",
		},
		{
			name: "valid workflow identity with fully qualified source - no default",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			buildOpts: &options.BuilderOpts{
				ExpectedID: asStringPointer("https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml"),
			},
			builderID: "https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml",
		},
		{
			name: "valid workflow identity with fully qualified source - match builderID",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			buildOpts: &options.BuilderOpts{
				ExpectedID: asStringPointer("https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml"),
			},
			defaults:  defaultArtifactTrustedReusableWorkflows,
			builderID: "https://github.com/" + trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml",
		},
		{
			name: "valid workflow identity with fully qualified source - mismatch builderID",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			buildOpts: &options.BuilderOpts{
				ExpectedID: asStringPointer("some-other-builderID"),
			},
			defaults: defaultArtifactTrustedReusableWorkflows,
			err:      serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name: "valid workflow identity with fully qualified source - mismatch defaults",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			defaults: defaultContainerTrustedReusableWorkflows,
			err:      serrors.ErrorUntrustedReusableWorkflow,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := tt.buildOpts
			if opts == nil {
				opts = &options.BuilderOpts{}
			}
			id, err := VerifyBuilderIdentity(tt.workflow, opts, tt.defaults)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
			}
			if err != nil {
				return
			}

			if err := id.MatchesLoose(tt.builderID, true); err != nil {
				t.Errorf("matches failed:%v", err)
			}
		})
	}
}

func Test_VerifyCertficateSourceRepository(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		workflow *WorkflowIdentity
		source   string
		err      error
	}{
		{
			name: "repo match",
			workflow: &WorkflowIdentity{
				SourceRepository:   "asraa/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			source: "github.com/asraa/slsa-on-github-test",
		},
		{
			name: "unexpected source for e2e test",
			workflow: &WorkflowIdentity{
				SourceRepository:   e2eTestRepository,
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			source: "malicious/source",
			err:    serrors.ErrorMismatchSource,
		},
		{
			name: "valid main ref for builder",
			workflow: &WorkflowIdentity{
				SourceRepository:   trustedBuilderRepository,
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			source: "malicious/source",
			err:    serrors.ErrorMismatchSource,
		},
		{
			name: "unexpected source",
			workflow: &WorkflowIdentity{
				SourceRepository:   "malicious/slsa-on-github-test",
				SourceSha1:         "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				SubjectWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				BuildTrigger:       "workflow_dispatch",
				Issuer:             certOidcIssuer,
			},
			source: "asraa/slsa-on-github-test",
			err:    serrors.ErrorMismatchSource,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyCertficateSourceRepository(tt.workflow, tt.source)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
			}
		})
	}
}

func asStringPointer(s string) *string {
	return &s
}

func Test_verifyTrustedBuilderID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		id       *string
		path     string
		tag      string
		defaults map[string]bool
		expected error
	}{
		{
			name:     "default trusted short tag",
			path:     trustedBuilderRepository + "/.github/workflows/generator_generic_slsa3.yml",
			tag:      "v1.2.3",
			defaults: defaultArtifactTrustedReusableWorkflows,
		},
		{
			name:     "default trusted long tag",
			path:     trustedBuilderRepository + "/.github/workflows/generator_generic_slsa3.yml",
			tag:      "refs/tags/v1.2.3",
			defaults: defaultArtifactTrustedReusableWorkflows,
		},
		{
			name:     "default mismatch against container defaults long tag",
			path:     trustedBuilderRepository + "/.github/workflows/generator_generic_slsa3.yml",
			tag:      "refs/tags/v1.2.3",
			defaults: defaultContainerTrustedReusableWorkflows,
			expected: serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name: "valid ID for GitHub builder short tag",
			path: "some/repo/someBuilderID",
			tag:  "v1.2.3",
			id:   asStringPointer("https://github.com/some/repo/someBuilderID@v1.2.3"),
		},
		{
			name: "valid ID for GitHub builder long tag",
			path: "some/repo/someBuilderID",
			tag:  "refs/tags/v1.2.3",
			id:   asStringPointer("https://github.com/some/repo/someBuilderID@refs/tags/v1.2.3"),
		},
		{
			name: "valid short ID for GitHub builder long tag",
			path: "some/repo/someBuilderID",
			tag:  "refs/tags/v1.2.3",
			id:   asStringPointer("https://github.com/some/repo/someBuilderID@v1.2.3"),
		},
		{
			name:     "valid long ID for GitHub builder short tag",
			path:     "some/repo/someBuilderID",
			tag:      "v1.2.3",
			id:       asStringPointer("https://github.com/some/repo/someBuilderID@refs/tags/v1.2.3"),
			expected: serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name: "valid ID for GitHub builder long tag",
			path: "some/repo/someBuilderID",
			tag:  "refs/tags/v1.2.3",
			id:   asStringPointer("https://github.com/some/repo/someBuilderID@refs/tags/v1.2.3"),
		},
		{
			name: "valid ID for GitHub builder short tag",
			path: "some/repo/someBuilderID",
			tag:  "v1.2.3",
			id:   asStringPointer("https://github.com/some/repo/someBuilderID@v1.2.3"),
		},
		{
			name: "valid short ID for GitHub builder long tag",
			path: "some/repo/someBuilderID",
			tag:  "refs/tags/v1.2.3",
			id:   asStringPointer("https://github.com/some/repo/someBuilderID@v1.2.3"),
		},
		{
			name:     "valid long ID for GitHub builder short tag",
			path:     "some/repo/someBuilderID",
			tag:      "v1.2.3",
			id:       asStringPointer("https://github.com/some/repo/someBuilderID@refs/tags/v1.2.3"),
			expected: serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name:     "non GitHub builder ID long builder tag",
			path:     "some/repo/someBuilderID",
			tag:      "refs/tags/v1.2.3",
			id:       asStringPointer("https://not-github.com/some/repo/someBuilderID"),
			expected: serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name:     "mismatch org GitHub short builder tag",
			path:     "some/repo/someBuilderID",
			tag:      "v1.2.3",
			id:       asStringPointer("https://github.com/other/repo/someBuilderID"),
			expected: serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name:     "mismatch org GitHub long builder tag",
			path:     "some/repo/someBuilderID",
			tag:      "refs/tags/v1.2.3",
			id:       asStringPointer("https://github.com/other/repo/someBuilderID"),
			expected: serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name:     "mismatch name GitHub long builder tag",
			path:     "some/repo/someBuilderID",
			tag:      "refs/tags/v1.2.3",
			id:       asStringPointer("https://github.com/some/other/someBuilderID"),
			expected: serrors.ErrorUntrustedReusableWorkflow,
		},
		{
			name:     "mismatch id GitHub long builder tag",
			path:     "some/repo/someBuilderID",
			tag:      "refs/tags/v1.2.3",
			id:       asStringPointer("https://github.com/some/repo/ID"),
			expected: serrors.ErrorUntrustedReusableWorkflow,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			id, err := verifyTrustedBuilderID(tt.path, tt.tag, tt.id, tt.defaults)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
			if err != nil {
				return
			}
			expectedID := "https://github.com/" + tt.path + "@" + tt.tag
			if err := id.MatchesLoose(expectedID, true); err != nil {
				t.Errorf("matches failed:%v", err)
			}
		})
	}
}

func Test_verifyTrustedBuilderRef(t *testing.T) {
	tests := []struct {
		name           string
		callerRepo     string
		builderRef     string
		expected       error
		testingEnabled bool
	}{
		// Trusted repo.
		{
			name:       "main not allowed for builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/heads/main",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:           "main allowed for builder w/ testing enabled",
			callerRepo:     trustedBuilderRepository,
			builderRef:     "refs/heads/main",
			testingEnabled: true,
		},
		{
			name:       "full semver for builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/tags/v1.2.3",
		},
		{
			name:       "no patch semver for other builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/tags/v1.2",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:       "no min semver for builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/tags/v1",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:       "full semver with prerelease for builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/tags/v1.2.3-alpha",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:       "full semver with build for builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/tags/v1.2.3+123",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:       "full semver with build/prerelease for builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/tags/v1.2.3-alpha+123",
			expected:   serrors.ErrorInvalidRef,
		},
		// E2e tests repo.
		{
			name:       "main not allowed for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/heads/main",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:           "main allowed for test repo w/ testing enabled",
			callerRepo:     e2eTestRepository,
			builderRef:     "refs/heads/main",
			testingEnabled: true,
		},

		{
			name:       "full semver for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/tags/v1.2.3",
		},
		{
			name:       "no patch semver for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/tags/v1.2",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:       "no min semver for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/tags/v1",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:       "full semver with prerelease for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/tags/v1.2.3-alpha",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:       "full semver with build for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/tags/v1.2.3+123",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:       "full semver with build/prerelease for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/tags/v1.2.3-alpha+123",
			expected:   serrors.ErrorInvalidRef,
		},
		// Other repos.
		{
			name:       "main not allowed for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/heads/main",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:           "main not allowed for other repos w/ testing enabled",
			callerRepo:     "some/repo",
			builderRef:     "refs/heads/main",
			testingEnabled: true,
			expected:       serrors.ErrorInvalidRef,
		},
		{
			name:       "full semver for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/tags/v1.2.3",
		},
		{
			name:       "no patch semver for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/tags/v1.2",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:       "no min semver for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/tags/v1",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:       "full semver with prerelease for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/tags/v1.2.3-alpha",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:           "full semver with prerelease for other repos w/ testing enabled",
			callerRepo:     "some/repo",
			builderRef:     "refs/tags/v1.2.3-alpha",
			testingEnabled: true,
			expected:       serrors.ErrorInvalidRef,
		},
		{
			name:       "full semver with build for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/tags/v1.2.3+123",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:           "full semver with build for other repos w/ testing enabled",
			callerRepo:     "some/repo",
			builderRef:     "refs/tags/v1.2.3+123",
			testingEnabled: true,
			expected:       serrors.ErrorInvalidRef,
		},
		{
			name:       "full semver with build/prerelease for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/tags/v1.2.3-alpha+123",
			expected:   serrors.ErrorInvalidRef,
		},
		{
			name:           "full semver with build/prerelease for other repos w/ testing enabled",
			callerRepo:     "some/repo",
			builderRef:     "refs/tags/v1.2.3-alpha+123",
			testingEnabled: true,
			expected:       serrors.ErrorInvalidRef,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			wf := WorkflowIdentity{
				SourceRepository: tt.callerRepo,
			}

			if tt.testingEnabled {
				t.Setenv("SLSA_VERIFIER_TESTING", "1")
			} else {
				// Ensure that the variable is not set.
				t.Setenv("SLSA_VERIFIER_TESTING", "")
			}

			err := verifyTrustedBuilderRef(&wf, tt.builderRef)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_GetWorkflowInfoFromCertificate(t *testing.T) {
	t.Parallel()
	// See https://github.com/sigstore/fulcio/blob/e763d76e3f7786b52db4b27ab87dc446da24895a/pkg/certificate/extensions.go.
	trigger := "workflow_dispatch"
	encodedTrigger, err := asn1.MarshalWithParams(trigger, "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}
	repo := "org/repo"
	encodedRepoURI, err := asn1.MarshalWithParams("https://github.com/"+repo, "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}
	issuer := "the-issuer"
	encodedIssuer, err := asn1.MarshalWithParams(issuer, "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}
	digest := "abcdef"
	encodedDigest, err := asn1.MarshalWithParams(digest, "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}
	encodedHosted, err := asn1.MarshalWithParams("github-hosted", "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}
	hosted := HostedGitHub
	ref := "refs/tags/v1.2.3"
	encodedRef, err := asn1.MarshalWithParams(ref, "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}
	sourceID := "12345"
	encodedSourceID, err := asn1.MarshalWithParams(sourceID, "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}
	sourceOwnerID := "12345"
	encodedSourceOwnerID, err := asn1.MarshalWithParams(sourceOwnerID, "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}

	buildConfigSha1 := "abcdef"
	encodedBuildConfigSha1, err := asn1.MarshalWithParams(buildConfigSha1, "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}
	buildConfigPath := "path/to/workflow"
	encodedBuildConfigURI, err := asn1.MarshalWithParams("https://github.com/"+repo+"/"+buildConfigPath+"@"+ref, "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}

	invocationID := "9207262"
	encodedInvocationURI, err := asn1.MarshalWithParams("https://github.com/"+repo+"/actions/runs/"+invocationID, "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}
	subjectSha1 := "subjectSha1"
	encodedSubjectSha1, err := asn1.MarshalWithParams(subjectSha1, "utf8")
	if err != nil {
		t.Errorf(err.Error())
	}

	tests := []struct {
		name     string
		cert     x509.Certificate
		workflow WorkflowIdentity
		err      error
	}{
		{
			name: "old cert",
			cert: x509.Certificate{
				URIs: []*url.URL{
					{
						Path: "/" + repo + "/" + buildConfigPath,
					},
				},
				Extensions: []pkix.Extension{
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDIssuer,
						Value: []byte(issuer),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowTrigger,
						Value: []byte(trigger),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowSHA,
						Value: []byte(digest),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowRepository,
						Value: []byte(repo),
					},
				},
			},
			workflow: WorkflowIdentity{
				Issuer:             issuer,
				SubjectWorkflowRef: repo + "/" + buildConfigPath,
				SourceRepository:   repo,
				SourceSha1:         digest,
				BuildTrigger:       trigger,
			},
		},
		{
			name: "old cert empty URIs",
			cert: x509.Certificate{
				Extensions: []pkix.Extension{
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDIssuer,
						Value: []byte(issuer),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowTrigger,
						Value: []byte(trigger),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowSHA,
						Value: []byte(digest),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowRepository,
						Value: []byte(repo),
					},
				},
			},
			err: serrors.ErrorInvalidFormat,
		},
		{
			name: "new cert",
			cert: x509.Certificate{
				URIs: []*url.URL{
					{
						Path: "/" + repo + "/" + buildConfigPath,
					},
				},
				Extensions: []pkix.Extension{
					// Deprecated claims.
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDIssuer,
						Value: []byte(issuer),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowTrigger,
						Value: []byte(trigger),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowSHA,
						Value: []byte(digest),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowRepository,
						Value: []byte(repo),
					},
					// New claims.
					{
						Id:    fulcio.OIDBuildTrigger,
						Value: encodedTrigger,
					},
					{
						Id:    fulcio.OIDSourceRepositoryURI,
						Value: encodedRepoURI,
					},
					{
						Id:    fulcio.OIDIssuerV2,
						Value: encodedIssuer,
					},
					{
						Id:    fulcio.OIDSourceRepositoryDigest,
						Value: encodedDigest,
					},
					{
						Id:    fulcio.OIDRunnerEnvironment,
						Value: encodedHosted,
					},
					{
						Id:    fulcio.OIDSourceRepositoryRef,
						Value: encodedRef,
					},
					{
						Id:    fulcio.OIDSourceRepositoryIdentifier,
						Value: encodedSourceID,
					},
					{
						Id:    fulcio.OIDSourceRepositoryOwnerIdentifier,
						Value: encodedSourceOwnerID,
					},
					{
						Id:    fulcio.OIDBuildConfigDigest,
						Value: encodedBuildConfigSha1,
					},
					{
						Id:    fulcio.OIDBuildConfigURI,
						Value: encodedBuildConfigURI,
					},
					{
						Id:    fulcio.OIDRunInvocationURI,
						Value: encodedInvocationURI,
					},
					{
						Id:    fulcio.OIDBuildSignerDigest,
						Value: encodedSubjectSha1,
					},
				},
			},
			workflow: WorkflowIdentity{
				Issuer:             issuer,
				SubjectSha1:        &subjectSha1,
				SubjectHosted:      &hosted,
				SubjectWorkflowRef: repo + "/" + buildConfigPath,
				SourceRepository:   repo,
				SourceSha1:         digest,
				SourceRef:          &ref,
				SourceID:           &sourceID,
				SourceOwnerID:      &sourceOwnerID,
				BuildTrigger:       trigger,
				BuildConfigPath:    &buildConfigPath,
				RunID:              &invocationID,
			},
		},
		{
			name: "new cert empty URIs",
			cert: x509.Certificate{
				Extensions: []pkix.Extension{
					// Deprecated claims.
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDIssuer,
						Value: []byte(issuer),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowTrigger,
						Value: []byte(trigger),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowSHA,
						Value: []byte(digest),
					},
					{
						//nolint: staticcheck // SA1019: Need to support older signatures.
						Id:    fulcio.OIDGitHubWorkflowRepository,
						Value: []byte(repo),
					},
					// New claims.
					{
						Id:    fulcio.OIDBuildTrigger,
						Value: encodedTrigger,
					},
					{
						Id:    fulcio.OIDSourceRepositoryURI,
						Value: encodedRepoURI,
					},
					{
						Id:    fulcio.OIDIssuerV2,
						Value: encodedIssuer,
					},
					{
						Id:    fulcio.OIDSourceRepositoryDigest,
						Value: encodedDigest,
					},
					{
						Id:    fulcio.OIDRunnerEnvironment,
						Value: encodedHosted,
					},
					{
						Id:    fulcio.OIDSourceRepositoryRef,
						Value: encodedRef,
					},
					{
						Id:    fulcio.OIDSourceRepositoryIdentifier,
						Value: encodedSourceID,
					},
					{
						Id:    fulcio.OIDSourceRepositoryOwnerIdentifier,
						Value: encodedSourceOwnerID,
					},
					{
						Id:    fulcio.OIDBuildConfigDigest,
						Value: encodedBuildConfigSha1,
					},
					{
						Id:    fulcio.OIDBuildConfigURI,
						Value: encodedBuildConfigURI,
					},
					{
						Id:    fulcio.OIDRunInvocationURI,
						Value: encodedInvocationURI,
					},
				},
			},
			err: serrors.ErrorInvalidFormat,
		},
		{
			name: "new cert no deprecated claims",
			cert: x509.Certificate{
				URIs: []*url.URL{
					{
						Path: "/" + repo + "/" + buildConfigPath,
					},
				},
				Extensions: []pkix.Extension{
					// New claims.
					{
						Id:    fulcio.OIDBuildTrigger,
						Value: encodedTrigger,
					},
					{
						Id:    fulcio.OIDSourceRepositoryURI,
						Value: encodedRepoURI,
					},
					{
						Id:    fulcio.OIDIssuerV2,
						Value: encodedIssuer,
					},
					{
						Id:    fulcio.OIDSourceRepositoryDigest,
						Value: encodedDigest,
					},
					{
						Id:    fulcio.OIDRunnerEnvironment,
						Value: encodedHosted,
					},
					{
						Id:    fulcio.OIDSourceRepositoryRef,
						Value: encodedRef,
					},
					{
						Id:    fulcio.OIDSourceRepositoryIdentifier,
						Value: encodedSourceID,
					},
					{
						Id:    fulcio.OIDSourceRepositoryOwnerIdentifier,
						Value: encodedSourceOwnerID,
					},
					{
						Id:    fulcio.OIDBuildConfigDigest,
						Value: encodedBuildConfigSha1,
					},
					{
						Id:    fulcio.OIDBuildConfigURI,
						Value: encodedBuildConfigURI,
					},
					{
						Id:    fulcio.OIDRunInvocationURI,
						Value: encodedInvocationURI,
					},
				},
			},
			workflow: WorkflowIdentity{
				Issuer:             issuer,
				SubjectWorkflowRef: repo + "/" + buildConfigPath,
				SourceRepository:   repo,
				SourceSha1:         digest,
				BuildTrigger:       trigger,
				SubjectHosted:      &hosted,
				SourceRef:          &ref,
				SourceID:           &sourceID,
				SourceOwnerID:      &sourceOwnerID,
				BuildConfigPath:    &buildConfigPath,
				RunID:              &invocationID,
			},
		},
		{
			name: "new cert no deprecated claims empty URIs",
			cert: x509.Certificate{
				Extensions: []pkix.Extension{
					// New claims.
					{
						Id:    fulcio.OIDBuildTrigger,
						Value: encodedTrigger,
					},
					{
						Id:    fulcio.OIDSourceRepositoryURI,
						Value: encodedRepoURI,
					},
					{
						Id:    fulcio.OIDIssuerV2,
						Value: encodedIssuer,
					},
					{
						Id:    fulcio.OIDSourceRepositoryDigest,
						Value: encodedDigest,
					},
					{
						Id:    fulcio.OIDRunnerEnvironment,
						Value: encodedHosted,
					},
					{
						Id:    fulcio.OIDSourceRepositoryRef,
						Value: encodedRef,
					},
					{
						Id:    fulcio.OIDSourceRepositoryIdentifier,
						Value: encodedSourceID,
					},
					{
						Id:    fulcio.OIDSourceRepositoryOwnerIdentifier,
						Value: encodedSourceOwnerID,
					},
					{
						Id:    fulcio.OIDBuildConfigDigest,
						Value: encodedBuildConfigSha1,
					},
					{
						Id:    fulcio.OIDBuildConfigURI,
						Value: encodedBuildConfigURI,
					},
					{
						Id:    fulcio.OIDRunInvocationURI,
						Value: encodedInvocationURI,
					},
				},
			},
			err: serrors.ErrorInvalidFormat,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			workflow, err := GetWorkflowInfoFromCertificate(&tt.cert)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
			}
			if err != nil {
				return
			}

			if !cmp.Equal(*workflow, tt.workflow) {
				t.Errorf(cmp.Diff(*workflow, tt.workflow))
			}
		})
	}
}
