package verification

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
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
