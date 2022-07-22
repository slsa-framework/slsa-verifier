package verification

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func Test_VerifyWorkflowIdentity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		workflow *WorkflowIdentity
		source   string
		err      error
	}{
		{
			name: "invalid job workflow ref",
			workflow: &WorkflowIdentity{
				CallerRepository:  "asraa/slsa-on-github-test",
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: "random/workflow/ref",
				Trigger:           "workflow_dispatch",
				Issuer:            "https://token.actions.githubusercontent.com",
			},
			source: "asraa/slsa-on-github-test",
			err:    errorMalformedWorkflowURI,
		},
		{
			name: "untrusted job workflow ref",
			workflow: &WorkflowIdentity{
				CallerRepository:  "asraa/slsa-on-github-test",
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: "/malicious/slsa-go/.github/workflows/builder.yml@refs/heads/main",
				Trigger:           "workflow_dispatch",
				Issuer:            "https://token.actions.githubusercontent.com",
			},
			source: "asraa/slsa-on-github-test",
			err:    ErrorUntrustedReusableWorkflow,
		},
		{
			name: "untrusted job workflow ref for general repos",
			workflow: &WorkflowIdentity{
				CallerRepository:  "asraa/slsa-on-github-test",
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/heads/main",
				Trigger:           "workflow_dispatch",
				Issuer:            "https://bad.issuer.com",
			},
			source: "asraa/slsa-on-github-test",
			err:    errorInvalidRef,
		},
		{
			name: "valid main ref for trusted builder",
			workflow: &WorkflowIdentity{
				CallerRepository:  trustedBuilderRepository,
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/heads/main",
				Trigger:           "workflow_dispatch",
				Issuer:            "https://token.actions.githubusercontent.com",
			},
			source: trustedBuilderRepository,
		},
		{
			name: "valid main ref for e2e test",
			workflow: &WorkflowIdentity{
				CallerRepository:  e2eTestRepository,
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/heads/main",
				Trigger:           "workflow_dispatch",
				Issuer:            certOidcIssuer,
			},
			source: e2eTestRepository,
		},
		{
			name: "unexpected source for e2e test",
			workflow: &WorkflowIdentity{
				CallerRepository:  e2eTestRepository,
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/heads/main",
				Trigger:           "workflow_dispatch",
				Issuer:            certOidcIssuer,
			},
			source: "malicious/source",
			err:    ErrorMismatchRepository,
		},
		{
			name: "valid main ref for builder",
			workflow: &WorkflowIdentity{
				CallerRepository:  trustedBuilderRepository,
				JobWobWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/heads/main",
				Trigger:           "workflow_dispatch",
				Issuer:            certOidcIssuer,
			},
			source: "malicious/source",
			err:    ErrorMismatchRepository,
		},
		{
			name: "unexpected source",
			workflow: &WorkflowIdentity{
				CallerRepository:  "malicious/slsa-on-github-test",
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				Trigger:           "workflow_dispatch",
				Issuer:            certOidcIssuer,
			},
			source: "asraa/slsa-on-github-test",
			err:    ErrorMismatchRepository,
		},
		{
			name: "valid workflow identity",
			workflow: &WorkflowIdentity{
				CallerRepository:  "asraa/slsa-on-github-test",
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				Trigger:           "workflow_dispatch",
				Issuer:            certOidcIssuer,
			},
			source: "asraa/slsa-on-github-test",
		},
		{
			name: "invalid workflow identity with prerelease",
			workflow: &WorkflowIdentity{
				CallerRepository:  "asraa/slsa-on-github-test",
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3-alpha",
				Trigger:           "workflow_dispatch",
				Issuer:            certOidcIssuer,
			},
			source: "asraa/slsa-on-github-test",
			err:    errorInvalidRef,
		},
		{
			name: "invalid workflow identity with build",
			workflow: &WorkflowIdentity{
				CallerRepository:  "asraa/slsa-on-github-test",
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3+123",
				Trigger:           "workflow_dispatch",
				Issuer:            certOidcIssuer,
			},
			source: "asraa/slsa-on-github-test",
			err:    errorInvalidRef,
		},
		{
			name: "invalid workflow identity with metadata",
			workflow: &WorkflowIdentity{
				CallerRepository:  "asraa/slsa-on-github-test",
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3-alpha+123",
				Trigger:           "workflow_dispatch",
				Issuer:            certOidcIssuer,
			},
			source: "asraa/slsa-on-github-test",
			err:    errorInvalidRef,
		},
		{
			name: "valid workflow identity with fully qualified source",
			workflow: &WorkflowIdentity{
				CallerRepository:  "asraa/slsa-on-github-test",
				CallerHash:        "0dfcd24824432c4ce587f79c918eef8fc2c44d7b",
				JobWobWorkflowRef: trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.3",
				Trigger:           "workflow_dispatch",
				Issuer:            certOidcIssuer,
			},
			source: "github.com/asraa/slsa-on-github-test",
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyWorkflowIdentity(tt.workflow, tt.source)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_verifyTrustedBuilderRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		callerRepo string
		builderRef string
		expected   error
	}{
		// Trusted repo.
		{
			name:       "main allowed for builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/heads/main",
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
			expected:   errorInvalidRef,
		},
		{
			name:       "no min semver for builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/tags/v1",
			expected:   errorInvalidRef,
		},
		{
			name:       "full semver with prerelease for builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/tags/v1.2.3-alpha",
			expected:   errorInvalidRef,
		},
		{
			name:       "full semver with build for builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/tags/v1.2.3+123",
			expected:   errorInvalidRef,
		},
		{
			name:       "full semver with build/prerelease for builder",
			callerRepo: trustedBuilderRepository,
			builderRef: "refs/tags/v1.2.3-alpha+123",
			expected:   errorInvalidRef,
		},
		// E2e tests repo.
		{
			name:       "main allowed for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/heads/main",
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
			expected:   errorInvalidRef,
		},
		{
			name:       "no min semver for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/tags/v1",
			expected:   errorInvalidRef,
		},
		{
			name:       "full semver with prerelease for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/tags/v1.2.3-alpha",
			expected:   errorInvalidRef,
		},
		{
			name:       "full semver with build for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/tags/v1.2.3+123",
			expected:   errorInvalidRef,
		},
		{
			name:       "full semver with build/prerelease for test repo",
			callerRepo: e2eTestRepository,
			builderRef: "refs/tags/v1.2.3-alpha+123",
			expected:   errorInvalidRef,
		},
		// Other repos.
		{
			name:       "main not allowed for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/heads/main",
			expected:   errorInvalidRef,
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
			expected:   errorInvalidRef,
		},
		{
			name:       "no min semver for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/tags/v1",
			expected:   errorInvalidRef,
		},
		{
			name:       "full semver with prerelease for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/tags/v1.2.3-alpha",
			expected:   errorInvalidRef,
		},
		{
			name:       "full semver with build for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/tags/v1.2.3+123",
			expected:   errorInvalidRef,
		},
		{
			name:       "full semver with build/prerelease for other repos",
			callerRepo: "some/repo",
			builderRef: "refs/tags/v1.2.3-alpha+123",
			expected:   errorInvalidRef,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			wf := WorkflowIdentity{
				CallerRepository: tt.callerRepo,
			}

			err := verifyTrustedBuilderRef(&wf, tt.builderRef)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}
