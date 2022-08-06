package gha

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
)

func provenanceFromBytes(payload []byte) (*intoto.ProvenanceStatement, error) {
	env, err := EnvelopeFromBytes(payload)
	if err != nil {
		return nil, err
	}
	return provenanceFromEnv(env)
}

func Test_VerifySha256Subject(t *testing.T) {
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
			expected:     serrors.ErrorInvalidDssePayload,
		},
		{
			name:         "invalid dsse: nil subject",
			path:         "./testdata/dsse-no-subject.intoto.jsonl",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     serrors.ErrorInvalidDssePayload,
		},
		{
			name:         "invalid dsse: no sha256 subject digest",
			path:         "./testdata/dsse-no-subject-hash.intoto.jsonl",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     serrors.ErrorInvalidDssePayload,
		},
		{
			name:         "mismatched artifact hash with env",
			path:         "./testdata/dsse-valid.intoto.jsonl",
			artifactHash: "1ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     serrors.ErrorMismatchHash,
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
			expected:     serrors.ErrorMismatchHash,
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
			prov, err := provenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("provenanceFromBytes: %w", err))
			}

			err = verifySha256Digest(prov, tt.artifactHash)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}

func Test_verifySourceURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		prov      *intoto.ProvenanceStatement
		sourceURI string
		expected  error
	}{
		{
			name: "source has no @",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Invocation: slsa.ProvenanceInvocation{
						ConfigSource: slsa.ConfigSource{
							URI: "git+https://github.com/some/repo",
						},
					},
				},
			},
			sourceURI: "git+https://github.com/some/repo",
			expected:  serrors.ErrorMalformedURI,
		},
		{
			name: "empty materials",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Invocation: slsa.ProvenanceInvocation{
						ConfigSource: slsa.ConfigSource{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
				},
			},
			sourceURI: "git+https://github.com/some/repo",
			expected:  serrors.ErrorInvalidDssePayload,
		},
		{
			name: "empty configSource",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
				},
			},
			sourceURI: "git+https://github.com/some/repo",
			expected:  serrors.ErrorMalformedURI,
		},
		{
			name: "empty uri materials",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "",
						},
					},
				},
			},
			sourceURI: "git+https://github.com/some/repo",
			expected:  serrors.ErrorMalformedURI,
		},
		{
			name: "no tag uri materials",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "git+https://github.com/some/repo",
						},
					},
				},
			},
			sourceURI: "git+https://github.com/some/repo",
			expected:  serrors.ErrorMalformedURI,
		},
		{
			name: "no tag uri configSource",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "git+https://github.com/some/repo",
						},
					},
				},
			},
			sourceURI: "git+https://github.com/some/repo",
			expected:  serrors.ErrorMalformedURI,
		},
		{
			name: "match source",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Invocation: slsa.ProvenanceInvocation{
						ConfigSource: slsa.ConfigSource{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
				},
			},
			sourceURI: "git+https://github.com/some/repo",
		},
		{
			name: "match source no git",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Invocation: slsa.ProvenanceInvocation{
						ConfigSource: slsa.ConfigSource{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
				},
			},
			sourceURI: "https://github.com/some/repo",
		},
		{
			name: "match source no git+https",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Invocation: slsa.ProvenanceInvocation{
						ConfigSource: slsa.ConfigSource{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
				},
			},
			sourceURI: "github.com/some/repo",
		},
		{
			name: "match source no repo",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Invocation: slsa.ProvenanceInvocation{
						ConfigSource: slsa.ConfigSource{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
				},
			},
			sourceURI: "some/repo",
			expected:  serrors.ErrorMalformedURI,
		},
		{
			name: "mismatch materials configSource tag",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Invocation: slsa.ProvenanceInvocation{
						ConfigSource: slsa.ConfigSource{
							URI: "git+https://github.com/some/repo@v1.2.4",
						},
					},
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
				},
			},
			sourceURI: "git+https://github.com/some/repo",
			expected:  serrors.ErrorInvalidDssePayload,
		},
		{
			name: "mismatch materials configSource org",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Invocation: slsa.ProvenanceInvocation{
						ConfigSource: slsa.ConfigSource{
							URI: "git+https://github.com/other/repo@v1.2.3",
						},
					},
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
				},
			},
			sourceURI: "git+https://github.com/some/repo",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name: "mismatch materials configSource name",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Invocation: slsa.ProvenanceInvocation{
						ConfigSource: slsa.ConfigSource{
							URI: "git+https://github.com/some/other@v1.2.3",
						},
					},
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "git+https://github.com/some/repo@v1.2.3",
						},
					},
				},
			},
			sourceURI: "git+https://github.com/some/repo",
			expected:  serrors.ErrorMismatchSource,
		},
		{
			name: "not github.com repo",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Invocation: slsa.ProvenanceInvocation{
						ConfigSource: slsa.ConfigSource{
							URI: "git+https://not-github.com/some/repo@v1.2.3",
						},
					},
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "git+https://not-github.com/some/repo@v1.2.3",
						},
					},
				},
			},
			sourceURI: "git+https://not-github.com/some/repo",
			expected:  serrors.ErrorMalformedURI,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := verifySourceURI(tt.prov, tt.sourceURI)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}

func Test_verifyBuilderID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		prov     *intoto.ProvenanceStatement
		id       string
		expected error
	}{
		{
			name: "id has no @",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Builder: slsa.ProvenanceBuilder{
						ID: "some/builderID",
					},
				},
			},
			id:       "some/builderID",
			expected: serrors.ErrorMalformedURI,
		},
		{
			name: "same builderID",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Builder: slsa.ProvenanceBuilder{
						ID: "some/builderID@v1.2.3",
					},
				},
			},
			id: "some/builderID",
		},
		{
			name: "same builderID full match",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Builder: slsa.ProvenanceBuilder{
						ID: "some/builderID@v1.2.3",
					},
				},
			},
			id: "some/builderID@v1.2.3",
		},
		{
			name: "same builderID mismatch version",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Builder: slsa.ProvenanceBuilder{
						ID: "some/builderID@v1.2.3",
					},
				},
			},
			id: "some/builderID@v1.2.4",
			// TODO(#189): this should fail.
		},
		{
			name: "mismatch builderID",
			prov: &intoto.ProvenanceStatement{
				Predicate: slsa.ProvenancePredicate{
					Builder: slsa.ProvenanceBuilder{
						ID: "tome/builderID@v1.2.3",
					},
				},
			},
			id:       "some/builderID",
			expected: serrors.ErrorMismatchBuilderID,
		},
		{
			name:     "empty builderID",
			prov:     &intoto.ProvenanceStatement{},
			id:       "some/builderID",
			expected: serrors.ErrorMalformedURI,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := verifyBuilderID(tt.prov, tt.id)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
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
			expected: serrors.ErrorInvalidDssePayload,
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
		{
			name:     "from commit push - no branch",
			path:     "./testdata/dsse-push-from-commit.intoto.jsonl",
			branch:   "main",
			expected: serrors.ErrorMismatchBranch,
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
			prov, err := provenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("provenanceFromBytes: %w", err))
			}

			err = VerifyBranch(prov, tt.branch)
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
			expected: serrors.ErrorMismatchTag,
		},
		{
			name:     "ref branch3",
			path:     "./testdata/dsse-branch3-ref.intoto.jsonl",
			expected: serrors.ErrorMismatchTag,
		},
		{
			name:     "invalid ref type",
			path:     "./testdata/dsse-invalid-ref-type.intoto.jsonl",
			expected: serrors.ErrorInvalidDssePayload,
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
			prov, err := provenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("provenanceFromBytes: %w", err))
			}

			err = VerifyTag(prov, tt.tag)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
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
			expected: serrors.ErrorInvalidSemver,
			tag:      "v1.2.3",
		},
		{
			name:     "ref branch3",
			path:     "./testdata/dsse-branch3-ref.intoto.jsonl",
			expected: serrors.ErrorInvalidSemver,
			tag:      "v1.2.3",
		},
		{
			name:     "tag v1.2 invalid versioning",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "1.2",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name:     "invalid ref",
			path:     "./testdata/dsse-invalid-ref-type.intoto.jsonl",
			expected: serrors.ErrorInvalidDssePayload,
			tag:      "v1.2.3",
		},
		{
			name:     "tag vslsa1 invalid",
			path:     "./testdata/dsse-vslsa1-tag.intoto.jsonl",
			tag:      "vslsa1",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name:     "tag vslsa1 invalid semver",
			path:     "./testdata/dsse-vslsa1-tag.intoto.jsonl",
			tag:      "v1.2.3",
			expected: serrors.ErrorInvalidSemver,
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
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3 no match v1.3",
			path:     "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:      "v1.3",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3 no match v1.2.4",
			path:     "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:      "v1.2.4",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3 no match v1.2.2",
			path:     "./testdata/dsse-v1.2.3-tag.intoto.jsonl",
			tag:      "v1.2.2",
			expected: serrors.ErrorMismatchVersionedTag,
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
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v0 no match v1.3",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v0",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2 no match v1.3",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1.3",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2 no match v1.2.3",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1.2.3",
			expected: serrors.ErrorMismatchVersionedTag,
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
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name:     "invalid v1.2-alpha",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1.2-alpha",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name:     "invalid v1-alpha",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1-alpha",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name:     "invalid v1+123",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1+123",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name:     "invalid v1-alpha+123",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1-alpha+123",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name:     "invalid v1.2-alpha+123",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v1.2-alpha+123",
			expected: serrors.ErrorInvalidSemver,
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
			expected: serrors.ErrorMismatchVersionedTag,
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
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3+123 no match v1.2.3-alpha+123",
			path:     "./testdata/dsse-v1.2.3+123-tag.intoto.jsonl",
			tag:      "v1.2.3-alpha+123",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3+123 no match v1.2.3-alpha",
			path:     "./testdata/dsse-v1.2.3+123-tag.intoto.jsonl",
			tag:      "v1.2.3-alpha",
			expected: serrors.ErrorMismatchVersionedTag,
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
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2.3-alpha no match v1.2.3-beta",
			path:     "./testdata/dsse-v1.2.3-alpha-tag.intoto.jsonl",
			tag:      "v1.2.3-beta",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2 no match v1.2.3-beta",
			path:     "./testdata/dsse-v1.2.3-alpha-tag.intoto.jsonl",
			tag:      "v1.2.3-beta",
			expected: serrors.ErrorMismatchVersionedTag,
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
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1.2 no match v2",
			path:     "./testdata/dsse-v1.2-tag.intoto.jsonl",
			tag:      "v2",
			expected: serrors.ErrorMismatchVersionedTag,
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
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1 no match v1.2",
			path:     "./testdata/dsse-v1-tag.intoto.jsonl",
			tag:      "v1.2",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1 no match v0",
			path:     "./testdata/dsse-v1-tag.intoto.jsonl",
			tag:      "v0",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name:     "tag v1 no match v1.2.3",
			path:     "./testdata/dsse-v1-tag.intoto.jsonl",
			tag:      "v1.2.3",
			expected: serrors.ErrorMismatchVersionedTag,
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
			expected: serrors.ErrorInvalidSemver,
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
			prov, err := provenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("provenanceFromBytes: %w", err))
			}

			err = VerifyVersionedTag(prov, tt.tag)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}
