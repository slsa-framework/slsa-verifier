package gha

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
)

type testProvenance struct {
	builderID         string
	sourceURI         string
	triggerURI        string
	subjects          []intoto.Subject
	branch            string
	tag               string
	buildTriggerPath  string
	systemParameters  map[string]any
	buildInvocationID string
	buildStartTime    *time.Time
	buildFinishTime   *time.Time
	noResolvedDeps    int
	workflowInputs    map[string]any
}

func (p *testProvenance) BuilderID() (string, error)           { return p.builderID, nil }
func (p *testProvenance) SourceURI() (string, error)           { return p.sourceURI, nil }
func (p *testProvenance) TriggerURI() (string, error)          { return p.triggerURI, nil }
func (p *testProvenance) Subjects() ([]intoto.Subject, error)  { return p.subjects, nil }
func (p *testProvenance) GetBranch() (string, error)           { return p.branch, nil }
func (p *testProvenance) GetTag() (string, error)              { return p.tag, nil }
func (p *testProvenance) GetBuildTriggerPath() (string, error) { return p.buildTriggerPath, nil }
func (p *testProvenance) GetSystemParameters() (map[string]any, error) {
	return p.systemParameters, nil
}
func (p *testProvenance) GetBuildInvocationID() (string, error)       { return p.buildInvocationID, nil }
func (p *testProvenance) GetBuildStartTime() (*time.Time, error)      { return p.buildStartTime, nil }
func (p *testProvenance) GetBuildFinishTime() (*time.Time, error)     { return p.buildFinishTime, nil }
func (p *testProvenance) GetNumberResolvedDependencies() (int, error) { return p.noResolvedDeps, nil }
func (p *testProvenance) GetWorkflowInputs() (map[string]interface{}, error) {
	return p.workflowInputs, nil
}

type testProvenanceV02 struct {
	testProvenance
	predicate slsa02.ProvenancePredicate
}

func (p *testProvenanceV02) Predicate() slsa02.ProvenancePredicate { return p.predicate }

type testProvenanceV1 struct {
	testProvenance
	predicate slsa1.ProvenancePredicate
}

func (p *testProvenanceV1) Predicate() slsa1.ProvenancePredicate { return p.predicate }

func provenanceFromBytes(payload []byte) (iface.Provenance, error) {
	env, err := EnvelopeFromBytes(payload)
	if err != nil {
		return nil, err
	}
	return slsaprovenance.ProvenanceFromEnvelope(env)
}

func Test_ProvenanceFromEnvelope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		expected error
	}{
		{
			name:     "invalid dsse: not SLSA predicate",
			path:     "./testdata/dsse-not-slsa.intoto.jsonl",
			expected: serrors.ErrorInvalidDssePayload,
		},
		{
			name:     "slsa 1.0 invalid dsse: not SLSA predicate",
			path:     "./testdata/dsse-not-slsa-v1.intoto.jsonl",
			expected: serrors.ErrorInvalidDssePayload,
		},
		// TODO(#573): add more compliance tests.
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatalf("os.ReadFile: %v", err)
			}
			_, err = provenanceFromBytes(content)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}

func Test_VerifyDigest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		prov         iface.Provenance
		artifactHash string
		expected     error
	}{
		{
			name: "invalid dsse: no sha256 subject digest",
			prov: &testProvenance{
				subjects: []intoto.Subject{
					{
						Digest: common.DigestSet{
							"sha1": "4506290e2e8feb1f34b27a044f7cc863c830ef6b",
						},
					},
				},
			},
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     serrors.ErrorMismatchHash,
		},

		{
			name:         "invalid dsse: nil subject",
			prov:         &testProvenance{},
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     serrors.ErrorMismatchHash,
		},
		{
			name: "mismatched artifact hash",
			prov: &testProvenance{
				subjects: []intoto.Subject{
					{
						Digest: common.DigestSet{
							"sha256": "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
				},
			},
			artifactHash: "1ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     serrors.ErrorMismatchHash,
		},
		{
			name: "valid hash",
			prov: &testProvenance{
				subjects: []intoto.Subject{
					{
						Digest: common.DigestSet{
							"sha256": "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
				},
			},
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
		},
		{
			name: "valid entry multiple subjects last entry",
			prov: &testProvenance{
				subjects: []intoto.Subject{
					{
						Digest: common.DigestSet{
							"sha256": "03e7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
					{
						Digest: common.DigestSet{
							"sha1": "4506290e2e8feb1f34b27a044f7cc863c830ef6b",
						},
					},
					{
						Digest: common.DigestSet{
							"sha256": "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
				},
			},
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
		},
		{
			name: "valid multiple subjects second entry",
			prov: &testProvenance{
				subjects: []intoto.Subject{
					{
						Digest: common.DigestSet{
							"sha256": "03e7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
					{
						Digest: common.DigestSet{
							"sha256": "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
					{
						Digest: common.DigestSet{
							"sha1": "4506290e2e8feb1f34b27a044f7cc863c830ef6b",
						},
					},
				},
			},
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
		},
		{
			name: "multiple subjects invalid hash",
			prov: &testProvenance{
				subjects: []intoto.Subject{
					{
						Digest: common.DigestSet{
							"sha256": "03e7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
					{
						Digest: common.DigestSet{
							"sha256": "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
					{
						Digest: common.DigestSet{
							"sha1": "4506290e2e8feb1f34b27a044f7cc863c830ef6b",
						},
					},
				},
			},
			artifactHash: "04e7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			expected:     serrors.ErrorMismatchHash,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := verifyDigest(tt.prov, tt.artifactHash); !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}

func Test_verifySourceURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		provMaterialsURI   string
		provTriggerURI     string
		expectedSourceURI  string
		allowNoMaterialRef bool
		err                error
	}{
		{
			name:              "source has no @",
			provMaterialsURI:  "git+https://github.com/some/repo",
			provTriggerURI:    "git+https://github.com/some/repo",
			expectedSourceURI: "git+https://github.com/some/repo",
			err:               serrors.ErrorMalformedURI,
		},
		{
			name:              "empty materials",
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			expectedSourceURI: "git+https://github.com/some/repo",
			err:               serrors.ErrorMalformedURI,
		},
		{
			name:              "empty configSource",
			provMaterialsURI:  "git+https://github.com/some/repo@v1.2.3",
			expectedSourceURI: "git+https://github.com/some/repo",
			err:               serrors.ErrorMalformedURI,
		},
		{
			name:              "empty uri materials",
			provMaterialsURI:  " ",
			expectedSourceURI: "git+https://github.com/some/repo",
			err:               serrors.ErrorMalformedURI,
		},
		{
			name:              "no tag uri materials",
			provTriggerURI:    "git+https://github.com/some/repo",
			expectedSourceURI: "git+https://github.com/some/repo",
			err:               serrors.ErrorMalformedURI,
		},
		{
			name:              "no tag uri configSource",
			provMaterialsURI:  "git+https://github.com/some/repo",
			expectedSourceURI: "git+https://github.com/some/repo",
			err:               serrors.ErrorMalformedURI,
		},
		{
			name:              "match source",
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/repo@v1.2.3",
			expectedSourceURI: "git+https://github.com/some/repo",
		},
		{
			name:              "match source no git",
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/repo@v1.2.3",
			expectedSourceURI: "https://github.com/some/repo",
		},
		{
			name:               "match source no git no material ref",
			provTriggerURI:     "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:   "git+https://github.com/some/repo",
			allowNoMaterialRef: true,
			expectedSourceURI:  "https://github.com/some/repo",
		},
		{
			name:              "match source no git no material ref ref not allowed",
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/repo",
			expectedSourceURI: "https://github.com/some/repo",
			err:               serrors.ErrorMalformedURI,
		},
		{
			name:              "match source no git+https",
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/repo@v1.2.3",
			expectedSourceURI: "github.com/some/repo",
		},
		{
			name:              "match source no repo",
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/repo@v1.2.3",
			expectedSourceURI: "some/repo",
			err:               serrors.ErrorMalformedURI,
		},
		{
			name:              "mismatch materials configSource tag",
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.4",
			provMaterialsURI:  "git+https://github.com/some/repo@v1.2.3",
			expectedSourceURI: "git+https://github.com/some/repo",
			err:               serrors.ErrorInvalidDssePayload,
		},
		{
			name:              "mismatch materials configSource org",
			provTriggerURI:    "git+https://github.com/other/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/repo@v1.2.3",
			expectedSourceURI: "git+https://github.com/some/repo",
			err:               serrors.ErrorMismatchSource,
		},
		{
			name:              "mismatch configSource materials org",
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/other/repo@v1.2.3",
			expectedSourceURI: "git+https://github.com/some/repo",
			err:               serrors.ErrorMismatchSource,
		},
		{
			name:              "mismatch materials configSource name",
			provTriggerURI:    "git+https://github.com/some/other@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/repo@v1.2.3",
			expectedSourceURI: "git+https://github.com/some/repo",
			err:               serrors.ErrorMismatchSource,
		},
		{
			name:              "mismatch configSource materials name",
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/other@v1.2.3",
			expectedSourceURI: "git+https://github.com/some/repo",
			err:               serrors.ErrorMismatchSource,
		},
		{
			name:              "not github.com repo",
			provTriggerURI:    "git+https://not-github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://not-github.com/some/repo@v1.2.3",
			expectedSourceURI: "git+https://not-github.com/some/repo",
			err:               serrors.ErrorMalformedURI,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov02 := &testProvenance{
				sourceURI:  tt.provMaterialsURI,
				triggerURI: tt.provTriggerURI,
			}

			err := verifySourceURI(prov02, tt.expectedSourceURI, tt.allowNoMaterialRef)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_isValidDelegatorBuilderID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		builderID string
		err       error
	}{
		{
			name:      "no @",
			builderID: "some/builderID",
			err:       serrors.ErrorInvalidBuilderID,
		},
		{
			name:      "invalid ref",
			builderID: "some/builderID@v1.2.3",
			err:       serrors.ErrorInvalidRef,
		},
		{
			name:      "invalid ref not tag",
			builderID: "some/builderID@refs/head/v1.2.3",
			err:       serrors.ErrorInvalidRef,
		},
		{
			name:      "invalid ref not full semver",
			builderID: "some/builderID@refs/heads/v1.2",
			err:       serrors.ErrorInvalidRef,
		},
		{
			name:      "valid builder",
			builderID: "some/builderID@refs/tags/v1.2.3",
		},
	}

	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov := &testProvenance{
				builderID: tt.builderID,
			}

			err := isValidDelegatorBuilderID(prov)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyBuilderIDExactMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		builderID  string
		expectedID string
		err        error
	}{
		{
			name:       "match no version",
			builderID:  "some/builderID",
			expectedID: "some/builderID",
		},
		{
			name:       "match with tag",
			builderID:  "some/builderID@v1.2.3",
			expectedID: "some/builderID@v1.2.3",
		},
		{
			name:       "same builderID mismatch version",
			builderID:  "some/builderID@v1.2.3",
			expectedID: "some/builderID@v1.2.4",
			err:        serrors.ErrorMismatchBuilderID,
			// TODO(#189): this should fail.
		},
		{
			name:       "mismatch builderID same version",
			builderID:  "tome/builderID@v1.2.3",
			expectedID: "some/builderID@v1.2.3",
			err:        serrors.ErrorMismatchBuilderID,
		},
		{
			name:       "empty prov builderID",
			builderID:  "",
			expectedID: "some/builderID",
			err:        serrors.ErrorMismatchBuilderID,
		},
		{
			name:       "empty expected builderID",
			builderID:  "tome/builderID@v1.2.3",
			expectedID: "",
			err:        serrors.ErrorMismatchBuilderID,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov := &testProvenance{
				builderID: tt.builderID,
			}

			err := verifyBuilderIDExactMatch(prov, tt.expectedID)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_VerifyBranch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		prov     iface.Provenance
		branch   string
		expected error
	}{
		{
			name: "branch slsa1",
			prov: &testProvenance{
				branch: "refs/heads/slsa1",
			},
			branch: "slsa1",
		},
		{
			name: "branch mismatch",
			prov: &testProvenance{
				branch: "refs/heads/slsa1",
			},
			branch:   "slsa2",
			expected: serrors.ErrorMismatchBranch,
		},
		{
			name: "case sensitive branch mismatch",
			prov: &testProvenance{
				branch: "refs/heads/slsa1",
			},
			branch:   "SLSA2",
			expected: serrors.ErrorMismatchBranch,
		},
		{
			name: "invalid ref type",
			prov: &testProvenance{
				branch: "refs/tags/slsa1",
			},
			branch:   "slsa1",
			expected: serrors.ErrorInvalidRef,
		},
		{
			name: "ref empty",
			prov: &testProvenance{
				branch: "",
			},
			expected: serrors.ErrorInvalidRef,
		},
		{
			name: "branch empty",
			prov: &testProvenance{
				branch: "refs/heads/",
			},
			expected: serrors.ErrorInvalidRef,
		},
	}

	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := VerifyBranch(tt.prov, tt.branch); !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}

func Test_VerifyWorkflowInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		prov     iface.Provenance
		inputs   map[string]string
		expected error
	}{
		{
			name: "match all",
			prov: &testProvenance{
				workflowInputs: map[string]any{
					"release_version": "v1.2.3",
					"some_bool":       "true",
					"some_integer":    "123",
				},
			},
			inputs: map[string]string{
				"release_version": "v1.2.3",
				"some_bool":       "true",
				"some_integer":    "123",
			},
		},
		{
			name: "match subset",
			prov: &testProvenance{
				workflowInputs: map[string]any{
					"release_version": "v1.2.3",
					"some_bool":       "true",
					"some_integer":    "123",
				},
			},
			inputs: map[string]string{
				"release_version": "v1.2.3",
				"some_integer":    "123",
			},
		},
		{
			name: "missing field",
			prov: &testProvenance{
				workflowInputs: map[string]any{
					"release_version": "v1.2.3",
					"some_bool":       "true",
					"some_integer":    "123",
				},
			},
			inputs: map[string]string{
				"release_version": "v1.2.3",
				"missing_field":   "123",
			},
			expected: serrors.ErrorMismatchWorkflowInputs,
		},
		{
			name: "mismatch field release_version",
			prov: &testProvenance{
				workflowInputs: map[string]any{
					"release_version": "v1.2.3",
					"some_bool":       "true",
					"some_integer":    "123",
				},
			},
			inputs: map[string]string{
				"release_version": "v1.2.4",
				"some_integer":    "123",
			},
			expected: serrors.ErrorMismatchWorkflowInputs,
		},
		{
			name: "mismatch field some_integer",
			prov: &testProvenance{
				workflowInputs: map[string]any{
					"release_version": "v1.2.3",
					"some_bool":       "true",
					"some_integer":    "123",
				},
			},
			inputs: map[string]string{
				"release_version": "v1.2.3",
				"some_integer":    "124",
			},
			expected: serrors.ErrorMismatchWorkflowInputs,
		},
		{
			name: "mismatch field some_integer",
			prov: &testProvenance{
				workflowInputs: map[string]any{
					"release_version": "v1.2.3",
					"some_bool":       "true",
					"some_integer":    "123",
				},
			},
			inputs: map[string]string{
				"release_version": "v1.2.3",
				"some_integer":    "124",
			},
			expected: serrors.ErrorMismatchWorkflowInputs,
		},
		{
			name: "no inputs",
			prov: &testProvenance{
				workflowInputs: map[string]any{},
			},
			inputs: map[string]string{
				"release_version": "v1.2.3",
				"some_bool":       "true",
				"some_integer":    "123",
			},
			expected: serrors.ErrorMismatchWorkflowInputs,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := VerifyWorkflowInputs(tt.prov, tt.inputs); !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}

func Test_VerifyTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		prov     iface.Provenance
		tag      string
		expected error
	}{
		{
			name: "tag vslsa1",
			prov: &testProvenance{
				tag: "refs/tags/vslsa1",
			},
			tag: "vslsa1",
		},
		{
			name: "tag mismatch",
			prov: &testProvenance{
				tag: "refs/tags/vslsa1",
			},
			tag:      "vslsa2",
			expected: serrors.ErrorMismatchTag,
		},
		{
			name: "case sensitive tag mismatch",
			prov: &testProvenance{
				tag: "refs/tags/vslsa1",
			},
			tag:      "vSLSA2",
			expected: serrors.ErrorMismatchTag,
		},
		{
			name: "invalid ref type",
			prov: &testProvenance{
				tag: "refs/heads/vslsa1",
			},
			tag:      "vslsa1",
			expected: serrors.ErrorInvalidRef,
		},
		{
			name: "ref empty",
			prov: &testProvenance{
				tag: "",
			},
			expected: serrors.ErrorInvalidRef,
		},
		{
			name: "tag empty",
			prov: &testProvenance{
				tag: "refs/tags/",
			},
			expected: serrors.ErrorInvalidRef,
		},
	}

	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := VerifyTag(tt.prov, tt.tag); !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}

func Test_VerifyVersionedTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		prov     iface.Provenance
		tag      string
		expected error
	}{
		{
			name:     "no tag",
			prov:     &testProvenance{},
			tag:      "v1.2.3",
			expected: serrors.ErrorInvalidRef,
		},
		{
			name: "tag v1.2 invalid expected version",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag:      "1.2",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name: "tag v1.2.3 invalid tag ref",
			prov: &testProvenance{
				tag: "refs/heads/v1.2.3",
			},
			tag:      "v1.2.3",
			expected: serrors.ErrorInvalidRef,
		},
		{
			name: "tag vslsa1 invalid",
			prov: &testProvenance{
				tag: "refs/tags/vslsa1",
			},
			tag:      "vslsa1",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name: "tag vslsa1 invalid semver",
			prov: &testProvenance{
				tag: "refs/tags/vslsa1",
			},
			tag:      "v1.2.3",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name: "tag v1.2.3 exact match",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3",
			},
			tag: "v1.2.3",
		},
		{
			name: "tag v1.2.3 match v1.2",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3",
			},
			tag: "v1.2",
		},
		{
			name: "tag v1.2.3 match v1",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3",
			},
			tag: "v1",
		},
		{
			name: "tag v1.2.3 no match v2",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3",
			},
			tag:      "v2",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3 no match v1.3",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3",
			},
			tag:      "v1.3",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3 no match v1.2.4",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3",
			},
			tag:      "v1.2.4",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3 no match v1.2.2",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3",
			},
			tag:      "v1.2.2",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2 exact v1.2",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag: "v1.2",
		},
		{
			name: "tag v1.2 match v1",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag: "v1",
		},
		{
			name: "tag v1.1 no match v1.3",
			prov: &testProvenance{
				tag: "refs/tags/v1.3",
			},
			tag:      "v1.1",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v0 no match v1.3",
			prov: &testProvenance{
				tag: "refs/tags/v1.3",
			},
			tag:      "v0",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.3 no match v1.2",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag:      "v1.3",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3 no match v1.2",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag:      "v1.2.3",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.0 match v1.2",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag: "v1.2.0",
		},
		{
			name: "tag v1.2 match v1.2.0+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag: "v1.2.0+123",
		},
		{
			name: "invalid v1.2+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag:      "v1.2+123",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name: "invalid v1.2-alpha",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag:      "v1.2-alpha",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name: "invalid v1-alpha",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag:      "v1-alpha",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name: "invalid v1+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag:      "v1+123",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name: "invalid v1-alpha+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag:      "v1-alpha+123",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name: "invalid v1.2-alpha+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},

			tag:      "v1.2-alpha+123",
			expected: serrors.ErrorInvalidSemver,
		},
		{
			name: "tag v1.2.3-alpha match v1.2.3-alpha",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3-alpha",
			},
			tag: "v1.2.3-alpha",
		},
		{
			name: "tag v1.2.3-alpha no match v1.2.3",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3-alpha",
			},
			tag:      "v1.2.3",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3-alpha+123 match v1.2.3-alpha",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3-alpha+123",
			},

			tag: "v1.2.3-alpha",
		},
		{
			name: "tag v1.2.3-alpha+123 match v1.2.3-alpha+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3-alpha+123",
			},
			tag: "v1.2.3-alpha+123",
		},
		{
			name: "tag v1.2.3-alpha+123 match v1.2.3-alpha+456",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3-alpha+123",
			},
			tag: "v1.2.3-alpha+456",
		},
		{
			name: "tag v1.2.3-alpha match v1.2.3-alpha+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3-alpha",
			},
			tag: "v1.2.3-alpha+123",
		},
		{
			name: "tag v1.2.3-alpha no match v1.2.3-beta+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3-alpha",
			},
			tag:      "v1.2.3-beta+123",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3+123 no match v1.2.3-alpha+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3+123",
			},
			tag:      "v1.2.3-alpha+123",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3+123 no match v1.2.3-alpha",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3+123",
			},
			tag:      "v1.2.3-alpha",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3+123 match v1.2.3+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3+123",
			},
			tag: "v1.2.3+123",
		},
		{
			name: "tag v1.2.3+123 match v1.2.3",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3+123",
			},
			tag: "v1.2.3",
		},
		{
			name: "tag v1.2.3+123 match v1.2.3+456",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3+123",
			},
			tag: "v1.2.3+456",
		},
		{
			name: "tag v1.2.3 no match v1.2.3-aplha",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3",
			},
			tag:      "v1.2.3-alpha",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3-alpha no match v1.2.3-beta",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3-alpha",
			},
			tag:      "v1.2.3-beta",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2 no match v1.2.3-beta",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag:      "v1.2.3-beta",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2.3 match v1.2.3+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2.3",
			},
			tag: "v1.2.3+123",
		},
		{
			name: "tag v1.2 no match v1.2.0-aplha+123",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag:      "v1.2.0-alpha+123",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1.2 no match v2",
			prov: &testProvenance{
				tag: "refs/tags/v1.2",
			},
			tag:      "v2",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1 exact match",
			prov: &testProvenance{
				tag: "refs/tags/v1",
			},
			tag: "v1",
		},
		{
			name: "tag v1 no match v2",
			prov: &testProvenance{
				tag: "refs/tags/v1",
			},
			tag:      "v2",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1 no match v1.2",
			prov: &testProvenance{
				tag: "refs/tags/v1",
			},
			tag:      "v1.2",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1 no match v0",
			prov: &testProvenance{
				tag: "refs/tags/v1",
			},
			tag:      "v0",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1 no match v1.2.3",
			prov: &testProvenance{
				tag: "refs/tags/v1",
			},
			tag:      "v1.2.3",
			expected: serrors.ErrorMismatchVersionedTag,
		},
		{
			name: "tag v1 match v1.0",
			prov: &testProvenance{
				tag: "refs/tags/v1",
			},
			tag: "v1.0",
		},
		{
			name: "tag v1 match v1.0.0",
			prov: &testProvenance{
				tag: "refs/tags/v1",
			},
			tag: "v1.0.0",
		},
		{
			name: "invalid v1-alpha",
			prov: &testProvenance{
				tag: "refs/tags/v1",
			},
			tag:      "v1-alpha",
			expected: serrors.ErrorInvalidSemver,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := VerifyVersionedTag(tt.prov, tt.tag); !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}
