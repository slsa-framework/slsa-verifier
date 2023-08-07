package gha

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsacommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
)

type testProvenance struct {
	builderID         string
	buildType         string
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
func (p *testProvenance) BuildType() (string, error)           { return p.buildType, nil }
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

func Test_VerifyDigest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		prov         iface.Provenance
		artifactHash string
		expected     error
	}{
		{
			name: "invalid short hash",
			prov: &testProvenance{
				subjects: []intoto.Subject{
					{
						Digest: slsacommon.DigestSet{
							"sha1": "4506290e2e8feb1f34b27a044f7cc863c830ef6b",
						},
					},
				},
			},
			// NOTE: the hash is one character short of sha256 hash.
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4",
			expected:     serrors.ErrorInvalidHash,
		},
		{
			name: "invalid dsse: no sha256 subject digest",
			prov: &testProvenance{
				subjects: []intoto.Subject{
					{
						Digest: slsacommon.DigestSet{
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
						Digest: slsacommon.DigestSet{
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
						Digest: slsacommon.DigestSet{
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
						Digest: slsacommon.DigestSet{
							"sha256": "03e7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
					{
						Digest: slsacommon.DigestSet{
							"sha1": "4506290e2e8feb1f34b27a044f7cc863c830ef6b",
						},
					},
					{
						Digest: slsacommon.DigestSet{
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
						Digest: slsacommon.DigestSet{
							"sha256": "03e7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
					{
						Digest: slsacommon.DigestSet{
							"sha256": "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
					{
						Digest: slsacommon.DigestSet{
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
						Digest: slsacommon.DigestSet{
							"sha256": "03e7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
					{
						Digest: slsacommon.DigestSet{
							"sha256": "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
						},
					},
					{
						Digest: slsacommon.DigestSet{
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
		provBuildType      string
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
			name:              "not github repo",
			provTriggerURI:    "git+https://notgithub.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://notgithub.com/some/repo@v1.2.3",
			expectedSourceURI: "git+https://notgithub.com/some/repo",
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
			name:              "match source no git no material ref (npm)",
			provBuildType:     common.NpmCLIBuildTypeV1,
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/repo",
			expectedSourceURI: "https://github.com/some/repo",
		},
		{
			name:              "mismatch source material ref (npm)",
			provBuildType:     common.NpmCLIBuildTypeV1,
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/repo@v1.2.4",
			expectedSourceURI: "https://github.com/some/repo",
			err:               serrors.ErrorInvalidDssePayload,
		},
		{
			name:              "match source no git no material ref (byob)",
			provBuildType:     common.BYOBBuildTypeV0,
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/repo",
			expectedSourceURI: "https://github.com/some/repo",
		},
		{
			name:              "mismatch source material ref (byob)",
			provBuildType:     common.BYOBBuildTypeV0,
			provTriggerURI:    "git+https://github.com/some/repo@v1.2.3",
			provMaterialsURI:  "git+https://github.com/some/repo@v1.2.4",
			expectedSourceURI: "https://github.com/some/repo",
			err:               serrors.ErrorInvalidDssePayload,
		},
		{
			name:              "match source no git no material ref",
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
				buildType:  tt.provBuildType,
				sourceURI:  tt.provMaterialsURI,
				triggerURI: tt.provTriggerURI,
			}

			err := verifySourceURI(prov02, tt.expectedSourceURI)
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

func Test_VerifyProvenance(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                 string
		env                  *dsselib.Envelope
		provenanceOpts       *options.ProvenanceOpts
		trustedBuilderIDName string
		byob                 bool
		expectedID           *string
		expected             error
	}{
		{
			name: "Verify Trusted (slsa-github-generator) Bazel Builder (v1.8.0",
			env: &dsselib.Envelope{
				PayloadType: "application/vnd.in-toto+json",
				Payload:     "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJmaWIiLCJkaWdlc3QiOnsic2hhMjU2IjoiY2FhYWRiYTI4NDY5MDVhYzQ3N2M3NzdlOTZhNjM2ZTFjMmUwNjdmZGY2ZmVkOTBlYzllZWNhNGRmMThkNmVkOSJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjEiLCJwcmVkaWNhdGUiOnsiYnVpbGREZWZpbml0aW9uIjp7ImJ1aWxkVHlwZSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9zbHNhLWZyYW1ld29yay9zbHNhLWdpdGh1Yi1nZW5lcmF0b3IvZGVsZWdhdG9yLWdlbmVyaWNAdjAiLCJleHRlcm5hbFBhcmFtZXRlcnMiOnsiaW5wdXRzIjp7InJla29yLWxvZy1wdWJsaWMiOmZhbHNlLCJ0YXJnZXRzIjoiLy9zcmM6ZmliIiwiZmxhZ3MiOiIiLCJuZWVkcy1ydW5maWxlcyI6ZmFsc2UsImluY2x1ZGVzLWphdmEiOmZhbHNlLCJ1c2VyLWphdmEtZGlzdHJpYnV0aW9uIjoib3JhY2xlIiwidXNlci1qYXZhLXZlcnNpb24iOiIxNyJ9LCJ2YXJzIjp7fX0sImludGVybmFsUGFyYW1ldGVycyI6eyJHSVRIVUJfQUNUT1JfSUQiOiI3ODk1MzYwNCIsIkdJVEhVQl9FVkVOVF9OQU1FIjoid29ya2Zsb3dfZGlzcGF0Y2giLCJHSVRIVUJfQkFTRV9SRUYiOiIiLCJHSVRIVUJfUkVGIjoicmVmcy9oZWFkcy9tYWluIiwiR0lUSFVCX1JFRl9UWVBFIjoiYnJhbmNoIiwiR0lUSFVCX1JFUE9TSVRPUlkiOiJlbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUiLCJHSVRIVUJfUkVQT1NJVE9SWV9JRCI6IjY0MjU3OTUxMSIsIkdJVEhVQl9SRVBPU0lUT1JZX09XTkVSX0lEIjoiNzg5NTM2MDQiLCJHSVRIVUJfUlVOX0FUVEVNUFQiOiIxIiwiR0lUSFVCX1JVTl9JRCI6IjU3ODgzNDIzODEiLCJHSVRIVUJfUlVOX05VTUJFUiI6IjEiLCJHSVRIVUJfU0hBIjoiYWI5YTQ1OGY2NTk4MjYyNWRkODM4ODQ0MjNmYTQ1OWEyMjY0ZTQyOSIsIkdJVEhVQl9UUklHR0VSSU5HX0FDVE9SX0lEIjoiNzg5NTM2MDQiLCJHSVRIVUJfV09SS0ZMT1dfUkVGIjoiZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlLy5naXRodWIvd29ya2Zsb3dzL3Rlc3QtdmVyaWZpZXIueWFtbEByZWZzL2hlYWRzL21haW4iLCJHSVRIVUJfV09SS0ZMT1dfU0hBIjoiYWI5YTQ1OGY2NTk4MjYyNWRkODM4ODQ0MjNmYTQ1OWEyMjY0ZTQyOSIsIkdJVEhVQl9FVkVOVF9QQVlMT0FEIjp7ImlucHV0cyI6bnVsbCwicmVmIjoicmVmcy9oZWFkcy9tYWluIiwicmVwb3NpdG9yeSI6eyJhbGxvd19mb3JraW5nIjp0cnVlLCJhcmNoaXZlX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL3thcmNoaXZlX2Zvcm1hdH17L3JlZn0iLCJhcmNoaXZlZCI6ZmFsc2UsImFzc2lnbmVlc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9hc3NpZ25lZXN7L3VzZXJ9IiwiYmxvYnNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvZ2l0L2Jsb2Jzey9zaGF9IiwiYnJhbmNoZXNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvYnJhbmNoZXN7L2JyYW5jaH0iLCJjbG9uZV91cmwiOiJodHRwczovL2dpdGh1Yi5jb20vZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlLmdpdCIsImNvbGxhYm9yYXRvcnNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvY29sbGFib3JhdG9yc3svY29sbGFib3JhdG9yfSIsImNvbW1lbnRzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2NvbW1lbnRzey9udW1iZXJ9IiwiY29tbWl0c191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9jb21taXRzey9zaGF9IiwiY29tcGFyZV91cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9jb21wYXJlL3tiYXNlfS4uLntoZWFkfSIsImNvbnRlbnRzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2NvbnRlbnRzL3srcGF0aH0iLCJjb250cmlidXRvcnNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvY29udHJpYnV0b3JzIiwiY3JlYXRlZF9hdCI6IjIwMjMtMDUtMThUMjI6MzE6MTNaIiwiZGVmYXVsdF9icmFuY2giOiJtYWluIiwiZGVwbG95bWVudHNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvZGVwbG95bWVudHMiLCJkZXNjcmlwdGlvbiI6IlRlc3RpbmcgZ2VuZXJpYyBwcm92ZW5hbmNlIHdpdGggQmF6ZWwgZm9yIFNMU0EgTGV2ZWwgMy4iLCJkaXNhYmxlZCI6ZmFsc2UsImRvd25sb2Fkc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9kb3dubG9hZHMiLCJldmVudHNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvZXZlbnRzIiwiZm9yayI6dHJ1ZSwiZm9ya3MiOjAsImZvcmtzX2NvdW50IjowLCJmb3Jrc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9mb3JrcyIsImZ1bGxfbmFtZSI6ImVudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZSIsImdpdF9jb21taXRzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2dpdC9jb21taXRzey9zaGF9IiwiZ2l0X3JlZnNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvZ2l0L3JlZnN7L3NoYX0iLCJnaXRfdGFnc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9naXQvdGFnc3svc2hhfSIsImdpdF91cmwiOiJnaXQ6Ly9naXRodWIuY29tL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS5naXQiLCJoYXNfZGlzY3Vzc2lvbnMiOmZhbHNlLCJoYXNfZG93bmxvYWRzIjp0cnVlLCJoYXNfaXNzdWVzIjpmYWxzZSwiaGFzX3BhZ2VzIjpmYWxzZSwiaGFzX3Byb2plY3RzIjp0cnVlLCJoYXNfd2lraSI6dHJ1ZSwiaG9tZXBhZ2UiOiIiLCJob29rc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9ob29rcyIsImh0bWxfdXJsIjoiaHR0cHM6Ly9naXRodWIuY29tL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZSIsImlkIjo2NDI1Nzk1MTEsImlzX3RlbXBsYXRlIjpmYWxzZSwiaXNzdWVfY29tbWVudF91cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9pc3N1ZXMvY29tbWVudHN7L251bWJlcn0iLCJpc3N1ZV9ldmVudHNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvaXNzdWVzL2V2ZW50c3svbnVtYmVyfSIsImlzc3Vlc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9pc3N1ZXN7L251bWJlcn0iLCJrZXlzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2tleXN7L2tleV9pZH0iLCJsYWJlbHNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvbGFiZWxzey9uYW1lfSIsImxhbmd1YWdlIjoiQysrIiwibGFuZ3VhZ2VzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2xhbmd1YWdlcyIsImxpY2Vuc2UiOnsia2V5IjoibWl0IiwibmFtZSI6Ik1JVCBMaWNlbnNlIiwibm9kZV9pZCI6Ik1EYzZUR2xqWlc1elpURXoiLCJzcGR4X2lkIjoiTUlUIiwidXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9saWNlbnNlcy9taXQifSwibWVyZ2VzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL21lcmdlcyIsIm1pbGVzdG9uZXNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvbWlsZXN0b25lc3svbnVtYmVyfSIsIm1pcnJvcl91cmwiOm51bGwsIm5hbWUiOiJzbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZSIsIm5vZGVfaWQiOiJSX2tnRE9Ka3o4TnciLCJub3RpZmljYXRpb25zX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL25vdGlmaWNhdGlvbnN7P3NpbmNlLGFsbCxwYXJ0aWNpcGF0aW5nfSIsIm9wZW5faXNzdWVzIjowLCJvcGVuX2lzc3Vlc19jb3VudCI6MCwib3duZXIiOnsiYXZhdGFyX3VybCI6Imh0dHBzOi8vYXZhdGFycy5naXRodWJ1c2VyY29udGVudC5jb20vdS83ODk1MzYwND92PTQiLCJldmVudHNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvZXZlbnRzey9wcml2YWN5fSIsImZvbGxvd2Vyc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9mb2xsb3dlcnMiLCJmb2xsb3dpbmdfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvZm9sbG93aW5ney9vdGhlcl91c2VyfSIsImdpc3RzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L2dpc3Rzey9naXN0X2lkfSIsImdyYXZhdGFyX2lkIjoiIiwiaHRtbF91cmwiOiJodHRwczovL2dpdGh1Yi5jb20vZW50ZXJhZ2E2IiwiaWQiOjc4OTUzNjA0LCJsb2dpbiI6ImVudGVyYWdhNiIsIm5vZGVfaWQiOiJNRFE2VlhObGNqYzRPVFV6TmpBMCIsIm9yZ2FuaXphdGlvbnNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvb3JncyIsInJlY2VpdmVkX2V2ZW50c191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9yZWNlaXZlZF9ldmVudHMiLCJyZXBvc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9yZXBvcyIsInNpdGVfYWRtaW4iOmZhbHNlLCJzdGFycmVkX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L3N0YXJyZWR7L293bmVyfXsvcmVwb30iLCJzdWJzY3JpcHRpb25zX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L3N1YnNjcmlwdGlvbnMiLCJ0eXBlIjoiVXNlciIsInVybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2In0sInByaXZhdGUiOmZhbHNlLCJwdWxsc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9wdWxsc3svbnVtYmVyfSIsInB1c2hlZF9hdCI6IjIwMjMtMDgtMDdUMTc6NTY6MjlaIiwicmVsZWFzZXNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvcmVsZWFzZXN7L2lkfSIsInNpemUiOjExMSwic3NoX3VybCI6ImdpdEBnaXRodWIuY29tOmVudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS5naXQiLCJzdGFyZ2F6ZXJzX2NvdW50IjowLCJzdGFyZ2F6ZXJzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL3N0YXJnYXplcnMiLCJzdGF0dXNlc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9zdGF0dXNlcy97c2hhfSIsInN1YnNjcmliZXJzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL3N1YnNjcmliZXJzIiwic3Vic2NyaXB0aW9uX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL3N1YnNjcmlwdGlvbiIsInN2bl91cmwiOiJodHRwczovL2dpdGh1Yi5jb20vZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlIiwidGFnc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS90YWdzIiwidGVhbXNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvdGVhbXMiLCJ0b3BpY3MiOltdLCJ0cmVlc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9naXQvdHJlZXN7L3NoYX0iLCJ1cGRhdGVkX2F0IjoiMjAyMy0wNS0xOVQwMToxOTozOVoiLCJ1cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZSIsInZpc2liaWxpdHkiOiJwdWJsaWMiLCJ3YXRjaGVycyI6MCwid2F0Y2hlcnNfY291bnQiOjAsIndlYl9jb21taXRfc2lnbm9mZl9yZXF1aXJlZCI6ZmFsc2V9LCJzZW5kZXIiOnsiYXZhdGFyX3VybCI6Imh0dHBzOi8vYXZhdGFycy5naXRodWJ1c2VyY29udGVudC5jb20vdS83ODk1MzYwND92PTQiLCJldmVudHNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvZXZlbnRzey9wcml2YWN5fSIsImZvbGxvd2Vyc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9mb2xsb3dlcnMiLCJmb2xsb3dpbmdfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvZm9sbG93aW5ney9vdGhlcl91c2VyfSIsImdpc3RzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L2dpc3Rzey9naXN0X2lkfSIsImdyYXZhdGFyX2lkIjoiIiwiaHRtbF91cmwiOiJodHRwczovL2dpdGh1Yi5jb20vZW50ZXJhZ2E2IiwiaWQiOjc4OTUzNjA0LCJsb2dpbiI6ImVudGVyYWdhNiIsIm5vZGVfaWQiOiJNRFE2VlhObGNqYzRPVFV6TmpBMCIsIm9yZ2FuaXphdGlvbnNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvb3JncyIsInJlY2VpdmVkX2V2ZW50c191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9yZWNlaXZlZF9ldmVudHMiLCJyZXBvc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9yZXBvcyIsInNpdGVfYWRtaW4iOmZhbHNlLCJzdGFycmVkX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L3N0YXJyZWR7L293bmVyfXsvcmVwb30iLCJzdWJzY3JpcHRpb25zX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L3N1YnNjcmlwdGlvbnMiLCJ0eXBlIjoiVXNlciIsInVybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2In0sIndvcmtmbG93IjoiLmdpdGh1Yi93b3JrZmxvd3MvdGVzdC12ZXJpZmllci55YW1sIn19LCJyZXNvbHZlZERlcGVuZGVuY2llcyI6W3sidXJpIjoiZ2l0K2h0dHBzOi8vZ2l0aHViLmNvbS9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGVAcmVmcy9oZWFkcy9tYWluIiwiZGlnZXN0Ijp7ImdpdENvbW1pdCI6ImFiOWE0NThmNjU5ODI2MjVkZDgzODg0NDIzZmE0NTlhMjI2NGU0MjkifX1dfSwicnVuRGV0YWlscyI6eyJidWlsZGVyIjp7ImlkIjoiaHR0cHM6Ly9naXRodWIuY29tL3Nsc2EtZnJhbWV3b3JrL3Nsc2EtZ2l0aHViLWdlbmVyYXRvci8uZ2l0aHViL3dvcmtmbG93cy9idWlsZGVyX2JhemVsX3Nsc2EzLnltbEByZWZzL3RhZ3MvdjEuOC4wIn0sIm1ldGFkYXRhIjp7Imludm9jYXRpb25JZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvYWN0aW9ucy9ydW5zLzU3ODgzNDIzODEvYXR0ZW1wdHMvMSJ9fX19",
				Signatures: []dsselib.Signature{
					{
						Sig:   "MEYCIQCNUV+hEskMPRhBHiYl6F8r8Uvg6Vmyhd7p+yq3mlMujgIhAOYsaMjJqVXnslgvRNThMwpyN0QD6LOiqKjHcitj+NRU",
						KeyID: "",
					},
				},
			},
			provenanceOpts: &options.ProvenanceOpts{
				ExpectedBranch:         nil,
				ExpectedTag:            nil,
				ExpectedVersionedTag:   nil,
				ExpectedDigest:         "caaadba2846905ac477c777e96a636e1c2e067fdf6fed90ec9eeca4df18d6ed9",
				ExpectedSourceURI:      "github.com/enteraga6/slsa-lvl3-generic-provenance-with-bazel-example",
				ExpectedBuilderID:      "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/delegator_lowperms-generic_slsa3.yml@refs/tags/v1.8.0",
				ExpectedWorkflowInputs: map[string]string{},
			},
			byob:                 true,
			trustedBuilderIDName: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/delegator_lowperms-generic_slsa3.yml@refs/tags/v1.8.0",
			expectedID:           nil,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			trustedBuilderID, tErr := utils.TrustedBuilderIDNew(tt.trustedBuilderIDName, true)
			if tErr != nil {
				t.Errorf("Provenance Verification FAILED. Error: %v", tErr)
			}

			err := VerifyProvenance(tt.env, tt.provenanceOpts, trustedBuilderID, tt.byob, tt.expectedID)
			if err != nil {
				t.Errorf("Provenance Verification FAILED. Error: %v", err)
			}
		})
	}
}

func Test_VerifyProvenance2(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                 string
		env                  *dsselib.Envelope
		provenanceOpts       *options.ProvenanceOpts
		trustedBuilderIDName string
		byob                 bool
		expectedID           *string
		expected             error
	}{
		{
			name: "Verify Un-Trusted (slsa-github-generator) Bazel Builder (from enteraga6/slsa-github-generator)",
			env: &dsselib.Envelope{
				PayloadType: "application/vnd.in-toto+json",
				Payload:     "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJmaWIiLCJkaWdlc3QiOnsic2hhMjU2IjoiY2FhYWRiYTI4NDY5MDVhYzQ3N2M3NzdlOTZhNjM2ZTFjMmUwNjdmZGY2ZmVkOTBlYzllZWNhNGRmMThkNmVkOSJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjEiLCJwcmVkaWNhdGUiOnsiYnVpbGREZWZpbml0aW9uIjp7ImJ1aWxkVHlwZSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9zbHNhLWZyYW1ld29yay9zbHNhLWdpdGh1Yi1nZW5lcmF0b3IvZGVsZWdhdG9yLWdlbmVyaWNAdjAiLCJleHRlcm5hbFBhcmFtZXRlcnMiOnsiaW5wdXRzIjp7InJla29yLWxvZy1wdWJsaWMiOmZhbHNlLCJ0YXJnZXRzIjoiLy9zcmM6ZmliIiwiZmxhZ3MiOiIiLCJuZWVkcy1ydW5maWxlcyI6ZmFsc2UsImluY2x1ZGVzLWphdmEiOmZhbHNlLCJ1c2VyLWphdmEtZGlzdHJpYnV0aW9uIjoib3JhY2xlIiwidXNlci1qYXZhLXZlcnNpb24iOiIxNyJ9LCJ2YXJzIjp7fX0sImludGVybmFsUGFyYW1ldGVycyI6eyJHSVRIVUJfQUNUT1JfSUQiOiI3ODk1MzYwNCIsIkdJVEhVQl9FVkVOVF9OQU1FIjoid29ya2Zsb3dfZGlzcGF0Y2giLCJHSVRIVUJfUkVGIjoicmVmcy9oZWFkcy9tYWluIiwiR0lUSFVCX1JFRl9UWVBFIjoiYnJhbmNoIiwiR0lUSFVCX1JFUE9TSVRPUlkiOiJlbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUiLCJHSVRIVUJfUkVQT1NJVE9SWV9JRCI6IjY0MjU3OTUxMSIsIkdJVEhVQl9SRVBPU0lUT1JZX09XTkVSX0lEIjoiNzg5NTM2MDQiLCJHSVRIVUJfUlVOX0FUVEVNUFQiOiIxIiwiR0lUSFVCX1JVTl9JRCI6IjU3ODg5NjM1NDUiLCJHSVRIVUJfUlVOX05VTUJFUiI6IjEiLCJHSVRIVUJfU0hBIjoiZGE2NDA0MDJhMTlhYmZlZTBhMTdiMDg4NmQ0Yjk1NzE5NTVkOTdmYyIsIkdJVEhVQl9UUklHR0VSSU5HX0FDVE9SX0lEIjoiNzg5NTM2MDQiLCJHSVRIVUJfV09SS0ZMT1dfUkVGIjoiZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlLy5naXRodWIvd29ya2Zsb3dzL3Rlc3QtdmVyaWZpZXItMi55YW1sQHJlZnMvaGVhZHMvbWFpbiIsIkdJVEhVQl9XT1JLRkxPV19TSEEiOiJkYTY0MDQwMmExOWFiZmVlMGExN2IwODg2ZDRiOTU3MTk1NWQ5N2ZjIiwiR0lUSFVCX0VWRU5UX1BBWUxPQUQiOnsiaW5wdXRzIjpudWxsLCJyZWYiOiJyZWZzL2hlYWRzL21haW4iLCJyZXBvc2l0b3J5Ijp7ImFsbG93X2ZvcmtpbmciOnRydWUsImFyY2hpdmVfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUve2FyY2hpdmVfZm9ybWF0fXsvcmVmfSIsImFyY2hpdmVkIjpmYWxzZSwiYXNzaWduZWVzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2Fzc2lnbmVlc3svdXNlcn0iLCJibG9ic191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9naXQvYmxvYnN7L3NoYX0iLCJicmFuY2hlc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9icmFuY2hlc3svYnJhbmNofSIsImNsb25lX3VybCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUuZ2l0IiwiY29sbGFib3JhdG9yc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9jb2xsYWJvcmF0b3Jzey9jb2xsYWJvcmF0b3J9IiwiY29tbWVudHNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvY29tbWVudHN7L251bWJlcn0iLCJjb21taXRzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2NvbW1pdHN7L3NoYX0iLCJjb21wYXJlX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2NvbXBhcmUve2Jhc2V9Li4ue2hlYWR9IiwiY29udGVudHNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvY29udGVudHMveytwYXRofSIsImNvbnRyaWJ1dG9yc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9jb250cmlidXRvcnMiLCJjcmVhdGVkX2F0IjoiMjAyMy0wNS0xOFQyMjozMToxM1oiLCJkZWZhdWx0X2JyYW5jaCI6Im1haW4iLCJkZXBsb3ltZW50c191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9kZXBsb3ltZW50cyIsImRlc2NyaXB0aW9uIjoiVGVzdGluZyBnZW5lcmljIHByb3ZlbmFuY2Ugd2l0aCBCYXplbCBmb3IgU0xTQSBMZXZlbCAzLiIsImRpc2FibGVkIjpmYWxzZSwiZG93bmxvYWRzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2Rvd25sb2FkcyIsImV2ZW50c191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9ldmVudHMiLCJmb3JrIjp0cnVlLCJmb3JrcyI6MCwiZm9ya3NfY291bnQiOjAsImZvcmtzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2ZvcmtzIiwiZnVsbF9uYW1lIjoiZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlIiwiZ2l0X2NvbW1pdHNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvZ2l0L2NvbW1pdHN7L3NoYX0iLCJnaXRfcmVmc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9naXQvcmVmc3svc2hhfSIsImdpdF90YWdzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2dpdC90YWdzey9zaGF9IiwiZ2l0X3VybCI6ImdpdDovL2dpdGh1Yi5jb20vZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlLmdpdCIsImhhc19kaXNjdXNzaW9ucyI6ZmFsc2UsImhhc19kb3dubG9hZHMiOnRydWUsImhhc19pc3N1ZXMiOmZhbHNlLCJoYXNfcGFnZXMiOmZhbHNlLCJoYXNfcHJvamVjdHMiOnRydWUsImhhc193aWtpIjp0cnVlLCJob21lcGFnZSI6IiIsImhvb2tzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2hvb2tzIiwiaHRtbF91cmwiOiJodHRwczovL2dpdGh1Yi5jb20vZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlIiwiaWQiOjY0MjU3OTUxMSwiaXNfdGVtcGxhdGUiOmZhbHNlLCJpc3N1ZV9jb21tZW50X3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2lzc3Vlcy9jb21tZW50c3svbnVtYmVyfSIsImlzc3VlX2V2ZW50c191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9pc3N1ZXMvZXZlbnRzey9udW1iZXJ9IiwiaXNzdWVzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2lzc3Vlc3svbnVtYmVyfSIsImtleXNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUva2V5c3sva2V5X2lkfSIsImxhYmVsc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9sYWJlbHN7L25hbWV9IiwibGFuZ3VhZ2UiOiJDKysiLCJsYW5ndWFnZXNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvbGFuZ3VhZ2VzIiwibGljZW5zZSI6eyJrZXkiOiJtaXQiLCJuYW1lIjoiTUlUIExpY2Vuc2UiLCJub2RlX2lkIjoiTURjNlRHbGpaVzV6WlRFeiIsInNwZHhfaWQiOiJNSVQiLCJ1cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL2xpY2Vuc2VzL21pdCJ9LCJtZXJnZXNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvbWVyZ2VzIiwibWlsZXN0b25lc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9taWxlc3RvbmVzey9udW1iZXJ9IiwibWlycm9yX3VybCI6bnVsbCwibmFtZSI6InNsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlIiwibm9kZV9pZCI6IlJfa2dET0prejhOdyIsIm5vdGlmaWNhdGlvbnNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvbm90aWZpY2F0aW9uc3s/c2luY2UsYWxsLHBhcnRpY2lwYXRpbmd9Iiwib3Blbl9pc3N1ZXMiOjAsIm9wZW5faXNzdWVzX2NvdW50IjowLCJvd25lciI6eyJhdmF0YXJfdXJsIjoiaHR0cHM6Ly9hdmF0YXJzLmdpdGh1YnVzZXJjb250ZW50LmNvbS91Lzc4OTUzNjA0P3Y9NCIsImV2ZW50c191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9ldmVudHN7L3ByaXZhY3l9IiwiZm9sbG93ZXJzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L2ZvbGxvd2VycyIsImZvbGxvd2luZ191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9mb2xsb3dpbmd7L290aGVyX3VzZXJ9IiwiZ2lzdHNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvZ2lzdHN7L2dpc3RfaWR9IiwiZ3JhdmF0YXJfaWQiOiIiLCJodG1sX3VybCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9lbnRlcmFnYTYiLCJpZCI6Nzg5NTM2MDQsImxvZ2luIjoiZW50ZXJhZ2E2Iiwibm9kZV9pZCI6Ik1EUTZWWE5sY2pjNE9UVXpOakEwIiwib3JnYW5pemF0aW9uc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9vcmdzIiwicmVjZWl2ZWRfZXZlbnRzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L3JlY2VpdmVkX2V2ZW50cyIsInJlcG9zX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L3JlcG9zIiwic2l0ZV9hZG1pbiI6ZmFsc2UsInN0YXJyZWRfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvc3RhcnJlZHsvb3duZXJ9ey9yZXBvfSIsInN1YnNjcmlwdGlvbnNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvc3Vic2NyaXB0aW9ucyIsInR5cGUiOiJVc2VyIiwidXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYifSwicHJpdmF0ZSI6ZmFsc2UsInB1bGxzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL3B1bGxzey9udW1iZXJ9IiwicHVzaGVkX2F0IjoiMjAyMy0wOC0wN1QxOTowODo1MVoiLCJyZWxlYXNlc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9yZWxlYXNlc3svaWR9Iiwic2l6ZSI6MTEzLCJzc2hfdXJsIjoiZ2l0QGdpdGh1Yi5jb206ZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlLmdpdCIsInN0YXJnYXplcnNfY291bnQiOjAsInN0YXJnYXplcnNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvc3RhcmdhemVycyIsInN0YXR1c2VzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL3N0YXR1c2VzL3tzaGF9Iiwic3Vic2NyaWJlcnNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvc3Vic2NyaWJlcnMiLCJzdWJzY3JpcHRpb25fdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUvc3Vic2NyaXB0aW9uIiwic3ZuX3VybCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9lbnRlcmFnYTYvc2xzYS1sdmwzLWdlbmVyaWMtcHJvdmVuYW5jZS13aXRoLWJhemVsLWV4YW1wbGUiLCJ0YWdzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL3RhZ3MiLCJ0ZWFtc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3JlcG9zL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS90ZWFtcyIsInRvcGljcyI6W10sInRyZWVzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlL2dpdC90cmVlc3svc2hhfSIsInVwZGF0ZWRfYXQiOiIyMDIzLTA1LTE5VDAxOjE5OjM5WiIsInVybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlIiwidmlzaWJpbGl0eSI6InB1YmxpYyIsIndhdGNoZXJzIjowLCJ3YXRjaGVyc19jb3VudCI6MCwid2ViX2NvbW1pdF9zaWdub2ZmX3JlcXVpcmVkIjpmYWxzZX0sInNlbmRlciI6eyJhdmF0YXJfdXJsIjoiaHR0cHM6Ly9hdmF0YXJzLmdpdGh1YnVzZXJjb250ZW50LmNvbS91Lzc4OTUzNjA0P3Y9NCIsImV2ZW50c191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9ldmVudHN7L3ByaXZhY3l9IiwiZm9sbG93ZXJzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L2ZvbGxvd2VycyIsImZvbGxvd2luZ191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9mb2xsb3dpbmd7L290aGVyX3VzZXJ9IiwiZ2lzdHNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvZ2lzdHN7L2dpc3RfaWR9IiwiZ3JhdmF0YXJfaWQiOiIiLCJodG1sX3VybCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9lbnRlcmFnYTYiLCJpZCI6Nzg5NTM2MDQsImxvZ2luIjoiZW50ZXJhZ2E2Iiwibm9kZV9pZCI6Ik1EUTZWWE5sY2pjNE9UVXpOakEwIiwib3JnYW5pemF0aW9uc191cmwiOiJodHRwczovL2FwaS5naXRodWIuY29tL3VzZXJzL2VudGVyYWdhNi9vcmdzIiwicmVjZWl2ZWRfZXZlbnRzX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L3JlY2VpdmVkX2V2ZW50cyIsInJlcG9zX3VybCI6Imh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlcnMvZW50ZXJhZ2E2L3JlcG9zIiwic2l0ZV9hZG1pbiI6ZmFsc2UsInN0YXJyZWRfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvc3RhcnJlZHsvb3duZXJ9ey9yZXBvfSIsInN1YnNjcmlwdGlvbnNfdXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYvc3Vic2NyaXB0aW9ucyIsInR5cGUiOiJVc2VyIiwidXJsIjoiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2Vycy9lbnRlcmFnYTYifSwid29ya2Zsb3ciOiIuZ2l0aHViL3dvcmtmbG93cy90ZXN0LXZlcmlmaWVyLTIueWFtbCJ9fSwicmVzb2x2ZWREZXBlbmRlbmNpZXMiOlt7InVyaSI6ImdpdCtodHRwczovL2dpdGh1Yi5jb20vZW50ZXJhZ2E2L3Nsc2EtbHZsMy1nZW5lcmljLXByb3ZlbmFuY2Utd2l0aC1iYXplbC1leGFtcGxlQHJlZnMvaGVhZHMvbWFpbiIsImRpZ2VzdCI6eyJnaXRDb21taXQiOiJkYTY0MDQwMmExOWFiZmVlMGExN2IwODg2ZDRiOTU3MTk1NWQ5N2ZjIn19XX0sInJ1bkRldGFpbHMiOnsiYnVpbGRlciI6eyJpZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9lbnRlcmFnYTYvc2xzYS1naXRodWItZ2VuZXJhdG9yLy5naXRodWIvd29ya2Zsb3dzL2J1aWxkZXJfYmF6ZWxfc2xzYTMueW1sQHJlZnMvdGFncy92MS4wLjEifSwibWV0YWRhdGEiOnsiaW52b2NhdGlvbklkIjoiaHR0cHM6Ly9naXRodWIuY29tL2VudGVyYWdhNi9zbHNhLWx2bDMtZ2VuZXJpYy1wcm92ZW5hbmNlLXdpdGgtYmF6ZWwtZXhhbXBsZS9hY3Rpb25zL3J1bnMvNTc4ODk2MzU0NS9hdHRlbXB0cy8xIn19fX0=",
				Signatures: []dsselib.Signature{
					{
						Sig:   "MEUCIQCLO33ZR7g+FaUKCXR3tncSjGv/mfDiGjPuk7NmHVryPQIgHhratRQrI/Kn4fgO9zK5vglyfrGwbhSJkuvnfUcD5UM=",
						KeyID: "",
					},
				},
			},
			provenanceOpts: &options.ProvenanceOpts{
				ExpectedBranch:         nil,
				ExpectedTag:            nil,
				ExpectedVersionedTag:   nil,
				ExpectedDigest:         "caaadba2846905ac477c777e96a636e1c2e067fdf6fed90ec9eeca4df18d6ed9",
				ExpectedSourceURI:      "github.com/enteraga6/slsa-lvl3-generic-provenance-with-bazel-example",
				ExpectedBuilderID:      "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/delegator_lowperms-generic_slsa3.yml@refs/tags/v1.7.0",
				ExpectedWorkflowInputs: map[string]string{},
			},
			byob:                 true,
			trustedBuilderIDName: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/delegator_lowperms-generic_slsa3.yml@refs/tags/v1.7.0",
			expectedID:           nil,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			trustedBuilderID, tErr := utils.TrustedBuilderIDNew(tt.trustedBuilderIDName, true)
			if tErr != nil {
				t.Errorf("Provenance Verification FAILED. Error: %v", tErr)
			}

			err := VerifyProvenance(tt.env, tt.provenanceOpts, trustedBuilderID, tt.byob, tt.expectedID)
			if err == nil {
				t.Errorf("Provenance Verification should have failed but DID NOT. Error: untrusted builder is trusted")
			}
		})
	}
}
