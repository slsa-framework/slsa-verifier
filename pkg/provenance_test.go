package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/index"
)

type searchResult struct {
	resp *index.SearchIndexOK
	err  error
}

func envelopeFromBytes(payload []byte) (env *dsselib.Envelope, err error) {
	env = &dsselib.Envelope{}
	err = json.Unmarshal(payload, env)
	return
}

type MockIndexClient struct {
	result searchResult
}

func (m *MockIndexClient) SearchIndex(params *index.SearchIndexParams, opts ...index.ClientOption) (*index.SearchIndexOK, error) {
	return m.result.resp, m.result.err
}

func (m *MockIndexClient) SetTransport(transport runtime.ClientTransport) {
}

func errCmp(e1, e2 error) bool {
	return errors.Is(e1, e2) || errors.Is(e2, e1)
}

func Test_GetRekorEntries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		artifactHash string
		res          searchResult
		expected     error
	}{
		{
			name:         "rekor search result error",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			res: searchResult{
				err: index.NewSearchIndexDefault(500),
			},
			expected: ErrorRekorSearch,
		},
		{
			name:         "no rekor entries found",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			res: searchResult{
				err: nil,
				resp: &index.SearchIndexOK{
					Payload: []string{},
				},
			},
			expected: ErrorRekorSearch,
		},
		{
			name:         "valid rekor entries found",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			res: searchResult{
				err: nil,
				resp: &index.SearchIndexOK{
					Payload: []string{"39d5109436c43dad92897d50f3b271aa456382875a922b28fedef9038b8f683a"},
				},
			},
			expected: nil,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var mClient client.Rekor
			mClient.Index = &MockIndexClient{result: tt.res}

			_, err := GetRekorEntries(&mClient, tt.artifactHash)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}

func Test_VerifyProvenance(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		path         string
		artifactHash string
		expected     error
	}{
		{
			name:         "invalid dsse: not SLSA predicate",
			path:         "./testdata/dsse-not-slsa.intoto.jsonl",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     ErrorInvalidDssePayload,
		},
		{
			name:         "invalid dsse: nil subject",
			path:         "./testdata/dsse-no-subject.intoto.jsonl",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     ErrorInvalidDssePayload,
		},
		{
			name:         "invalid dsse: no sha256 subject digest",
			path:         "./testdata/dsse-no-subject-hash.intoto.jsonl",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     ErrorInvalidDssePayload,
		},
		{
			name:         "mismatched artifact hash with env",
			path:         "./testdata/dsse-valid.intoto.jsonl",
			artifactHash: "1ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     errorMismatchHash,
		},
		{
			name:         "valid entry",
			path:         "./testdata/dsse-valid.intoto.jsonl",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     nil,
		},
		{
			name:         "valid entry multiple subjects last entry",
			path:         "./testdata/dsse-valid-multi-subjects.intoto.jsonl",
			artifactHash: "03e7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     nil,
		},
		{
			name:         "valid multiple subjects second entry",
			path:         "./testdata/dsse-valid-multi-subjects.intoto.jsonl",
			artifactHash: "02e7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     nil,
		},
		{
			name:         "multiple subjects invalid hash",
			path:         "./testdata/dsse-valid-multi-subjects.intoto.jsonl",
			artifactHash: "04e7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     errorMismatchHash,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}
			env, err := envelopeFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("envelopeFromBytes: %w", err))
			}

			err = VerifyProvenance(env, tt.artifactHash)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}

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

func Test_VerifyBranch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		branch   string
		expected error
	}{
		{
			name:   "ref main",
			path:   "./testdata/dsse-main-ref.intoto.jsonl",
			branch: "main",
		},
		{
			name:   "ref branch3",
			path:   "./testdata/dsse-branch3-ref.intoto.jsonl",
			branch: "branch3",
		},
		{
			name:     "invalid ref type",
			path:     "./testdata/dsse-invalid-ref-type.intoto.jsonl",
			expected: ErrorInvalidDssePayload,
		},
		{
			name:   "tag branch2 push trigger",
			path:   "./testdata/dsse-branch2-tag.intoto.jsonl",
			branch: "branch2",
		},
		{
			name:   "v10.0.1 release trigger",
			path:   "./testdata/dsse-v10.0.1-release.intoto.jsonl",
			branch: "main",
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}
			env, err := envelopeFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("envelopeFromBytes: %w", err))
			}

			err = VerifyBranch(env, tt.branch)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}

func Test_VerifyTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		tag      string
		expected error
	}{
		{
			name:     "ref main",
			path:     "./testdata/dsse-main-ref.intoto.jsonl",
			expected: ErrorMismatchTag,
		},
		{
			name:     "ref branch3",
			path:     "./testdata/dsse-branch3-ref.intoto.jsonl",
			expected: ErrorMismatchTag,
		},
		{
			name:     "invalid ref type",
			path:     "./testdata/dsse-invalid-ref-type.intoto.jsonl",
			expected: ErrorInvalidDssePayload,
		},
		{
			name: "tag vslsa1",
			path: "./testdata/dsse-vslsa1-tag.intoto.jsonl",
			tag:  "vslsa1",
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}
			env, err := envelopeFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("envelopeFromBytes: %w", err))
			}

			err = VerifyTag(env, tt.tag)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
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

func Test_VerifyVersionedTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		tag      string
		expected error
	}{
		{
			name:     "ref main",
			path:     "./testdata/dsse-main-ref.intoto.jsonl",
			expected: ErrorInvalidSemver,
			tag:      "v1.2.3",
		},
		{
			name:     "ref branch3",
			path:     "./testdata/dsse-branch3-ref.intoto.jsonl",
			expected: ErrorInvalidSemver,
			tag:      "v1.2.3",
		},
		{
			name:     "tag v1.2 invalid versioning",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "1.2",
			expected: ErrorInvalidSemver,
		},
		{
			name:     "invalid ref",
			path:     "./testdata/dsse-invalid-ref-type.intoto.jsonl",
			expected: ErrorInvalidDssePayload,
			tag:      "v1.2.3",
		},
		{
			name:     "tag vslsa1 invalid",
			path:     "./testdata/dsse-vslsa1-tag.intoto.jsonl",
			tag:      "vslsa1",
			expected: ErrorInvalidSemver,
		},
		{
			name:     "tag vslsa1 invalid semver",
			path:     "./testdata/dsse-vslsa1-tag.intoto.jsonl",
			tag:      "v1.2.3",
			expected: ErrorInvalidSemver,
		},
		{
			name: "tag v1.2.3 exact match",
			path: "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:  "v1.2.3",
		},
		{
			name: "tag v1.2.3 match v1.2",
			path: "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:  "v1.2",
		},
		{
			name: "tag v1.2.3 match v1",
			path: "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:  "v1",
		},
		{
			name:     "tag v1.2.3 no match v2",
			path:     "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:      "v2",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3 no match v1.3",
			path:     "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:      "v1.3",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3 no match v1.2.4",
			path:     "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:      "v1.2.4",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3 no match v1.2.2",
			path:     "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:      "v1.2.2",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2 exact v1.2",
			path: "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:  "v1.2",
		},
		{
			name: "tag v1.2 match v1",
			path: "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:  "v1",
		},
		{
			name:     "tag v1.1 no match v1.3",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1.1",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v0 no match v1.3",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v0",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2 no match v1.3",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1.3",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2 no match v1.2.3",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1.2.3",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2 match v1.2.0",
			path: "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:  "v1.2.0",
		},
		{
			name: "tag v1.2 match v1.2.0+123",
			path: "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:  "v1.2.0+123",
		},
		{
			name:     "invalid v1.2+123",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1.2+123",
			expected: ErrorInvalidSemver,
		},
		{
			name:     "invalid v1.2-alpha",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1.2-alpha",
			expected: ErrorInvalidSemver,
		},
		{
			name:     "invalid v1-alpha",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1-alpha",
			expected: ErrorInvalidSemver,
		},
		{
			name:     "invalid v1+123",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1+123",
			expected: ErrorInvalidSemver,
		},
		{
			name:     "invalid v1-alpha+123",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1-alpha+123",
			expected: ErrorInvalidSemver,
		},
		{
			name:     "invalid v1.2-alpha+123",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1.2-alpha+123",
			expected: ErrorInvalidSemver,
		},
		{
			name: "tag v1.2.3-alpha match v1.2.3-alpha",
			path: "./testdata/dsse-v1.2.3-alpha-tag.intoto.jsonl",
			tag:  "v1.2.3-alpha",
		},
		{
			name:     "tag v1.2.3-alpha no match v1.2.3",
			path:     "./testdata/dsse-v1.2.3-alpha-tag.intoto.jsonl",
			tag:      "v1.2.3",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3-alpha+123 match v1.2.3-alpha",
			path: "./testdata/dsse-v1.2.3-alpha+123-tag.intoto.jsonl",
			tag:  "v1.2.3-alpha",
		},
		{
			name: "tag v1.2.3-alpha+123 match v1.2.3-alpha+123",
			path: "./testdata/dsse-v1.2.3-alpha+123-tag.intoto.jsonl",
			tag:  "v1.2.3-alpha+123",
		},
		{
			name: "tag v1.2.3-alpha+123 match v1.2.3-alpha+456",
			path: "./testdata/dsse-v1.2.3-alpha+123-tag.intoto.jsonl",
			tag:  "v1.2.3-alpha+456",
		},
		{
			name: "tag v1.2.3-alpha match v1.2.3-alpha+123",
			path: "./testdata/dsse-v1.2.3-alpha-tag.intoto.jsonl",
			tag:  "v1.2.3-alpha+123",
		},
		{
			name:     "tag v1.2.3-alpha no match v1.2.3-beta+123",
			path:     "./testdata/dsse-v1.2.3-alpha-tag.intoto.jsonl",
			tag:      "v1.2.3-beta+123",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3+123 no match v1.2.3-alpha+123",
			path:     "./testdata/dsse-v1.2.3+123-tag.intoto.jsonl",
			tag:      "v1.2.3-alpha+123",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3+123 no match v1.2.3-alpha",
			path:     "./testdata/dsse-v1.2.3+123-tag.intoto.jsonl",
			tag:      "v1.2.3-alpha",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3+123 match v1.2.3+123",
			path: "./testdata/dsse-v1.2.3+123-tag.intoto.jsonl",
			tag:  "v1.2.3+123",
		},
		{
			name: "tag v1.2.3+123 match v1.2.3",
			path: "./testdata/dsse-v1.2.3+123-tag.intoto.jsonl",
			tag:  "v1.2.3",
		},
		{
			name: "tag v1.2.3+123 match v1.2.3+456",
			path: "./testdata/dsse-v1.2.3+123-tag.intoto.jsonl",
			tag:  "v1.2.3+456",
		},
		{
			name:     "tag v1.2.3 no match v1.2.3-aplha",
			path:     "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:      "v1.2.3-alpha",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3-alpha no match v1.2.3-beta",
			path:     "./testdata/dsse-v1.2.3-alpha-tag.intoto.jsonl",
			tag:      "v1.2.3-beta",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2 no match v1.2.3-beta",
			path:     "./testdata/dsse-v1.2.3-alpha-tag.intoto.jsonl",
			tag:      "v1.2.3-beta",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3 match v1.2.3+123",
			path: "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:  "v1.2.3+123",
		},
		{
			name:     "tag v1.2 no match v1.2.0-aplha+123",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1.2.0-alpha+123",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2 no match v2",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v2",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1 exact match",
			path: "./testdata/dsse-v1-tag.intoto.jsonl",
			tag:  "v1",
		},
		{
			name:     "tag v1 no match v2",
			path:     "./testdata/dsse-v1-tag.intoto.jsonl",
			tag:      "v2",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1 no match v1.2",
			path:     "./testdata/dsse-v1-tag.intoto.jsonl",
			tag:      "v1.2",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1 no match v0",
			path:     "./testdata/dsse-v1-tag.intoto.jsonl",
			tag:      "v0",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1 no match v1.2.3",
			path:     "./testdata/dsse-v1-tag.intoto.jsonl",
			tag:      "v1.2.3",
			expected: ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1 match v1.0",
			path: "./testdata/dsse-v1-tag.intoto.jsonl",
			tag:  "v1.0",
		},
		{
			name: "tag v1 match v1.0.0",
			path: "./testdata/dsse-v1-tag.intoto.jsonl",
			tag:  "v1.0.0",
		},
		{
			name:     "invalid v1-alpha",
			path:     "./testdata/dsse-v1-tag.intoto.jsonl",
			tag:      "v1-alpha",
			expected: ErrorInvalidSemver,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}
			env, err := envelopeFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("envelopeFromBytes: %w", err))
			}

			err = VerifyVersionedTag(env, tt.tag)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}
