package v1

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func Test_BYOBProvenance_GetBranch(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		prov   BYOBProvenance
		branch string
		err    error
	}{
		{
			name: "empty provenance",
			prov: BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						StatementHeader: intoto.StatementHeader{},
						Predicate:       slsa1.ProvenancePredicate{},
					},
				},
			},
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "resolved dependency uri @ refs/heads/main",
			prov: BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						StatementHeader: intoto.StatementHeader{},
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ResolvedDependencies: []slsa1.ResourceDescriptor{
									{
										URI: "git+https://github.com/kubernetes/kubernetes@refs/heads/main",
									},
								},
							},
						},
					},
				},
			},
			branch: "refs/heads/main",
		},
		{
			name: "internalParameters uri @ refs/heads/main",
			prov: BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						StatementHeader: intoto.StatementHeader{},
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								InternalParameters: map[string]interface{}{
									"GITHUB_REF_TYPE": "branch",
									"GITHUB_REF":      "refs/heads/main",
								},
							},
						},
					},
				},
			},
			branch: "refs/heads/main",
		},
		{
			name: "resolved dependency uri @ refs/tags/v1.0.0",
			prov: BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						StatementHeader: intoto.StatementHeader{},
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								InternalParameters: map[string]interface{}{
									"GITHUB_BASE_REF":   "",
									"GITHUB_REF_TYPE":   "tag",
									"GITHUB_REF":        "refs/tags/v1.0.0",
									"GITHUB_EVENT_NAME": "push",
									"GITHUB_EVENT_PAYLOAD": map[string]any{
										"base_ref": nil,
									},
								},
								ResolvedDependencies: []slsa1.ResourceDescriptor{
									{
										URI: "git+https://github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
									},
								},
							},
						},
					},
				},
			},
			branch: "",
		},
		{
			name: "resolved dependency uri @ refs/heads/main no ref",
			prov: BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						StatementHeader: intoto.StatementHeader{},
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								InternalParameters: map[string]interface{}{
									"GITHUB_REF_TYPE": "branch",
									"GITHUB_REF":      "refs/heads/main",
								},
								ResolvedDependencies: []slsa1.ResourceDescriptor{
									{
										URI: "git+https://github.com/kubernetes/kubernetes",
									},
								},
							},
						},
					},
				},
			},
			err: serrors.ErrorInvalidDssePayload,
		},
	}

	for i := range testCases {
		tt := testCases[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			branch, err := tt.prov.GetBranch()
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got): \n%s", diff)
			}
			if got, want := branch, tt.branch; got != want {
				t.Fatalf("unexpected branch, got: %q, want: %q", got, want)
			}
		})
	}
}

func Test_BYOBProvenance_GetTag(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		prov BYOBProvenance
		tag  string
		err  error
	}{
		{
			name: "empty provenance",
			prov: BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						StatementHeader: intoto.StatementHeader{},
						Predicate:       slsa1.ProvenancePredicate{},
					},
				},
			},
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "resolved dependency uri @ refs/heads/main",
			prov: BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						StatementHeader: intoto.StatementHeader{},
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ResolvedDependencies: []slsa1.ResourceDescriptor{
									{
										URI: "git+https://github.com/kubernetes/kubernetes@refs/heads/main",
									},
								},
							},
						},
					},
				},
			},
			tag: "",
		},
		{
			name: "internalParameters uri @ refs/heads/main",
			prov: BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						StatementHeader: intoto.StatementHeader{},
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								InternalParameters: map[string]interface{}{
									"GITHUB_REF_TYPE": "branch",
									"GITHUB_REF":      "refs/heads/main",
								},
							},
						},
					},
				},
			},
			tag: "",
		},
		{
			name: "resolved dependency uri @ refs/tags/v1.0.0",
			prov: BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						StatementHeader: intoto.StatementHeader{},
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ResolvedDependencies: []slsa1.ResourceDescriptor{
									{
										URI: "git+https://github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
									},
								},
							},
						},
					},
				},
			},
			tag: "refs/tags/v1.0.0",
		},
		{
			name: "internalParameters uri @ ref/tags/v1.0.0",
			prov: BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						StatementHeader: intoto.StatementHeader{},
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								InternalParameters: map[string]interface{}{
									"GITHUB_REF_TYPE": "tag",
									"GITHUB_REF":      "refs/tags/v1.0.0",
								},
							},
						},
					},
				},
			},
			tag: "refs/tags/v1.0.0",
		},
		{
			name: "resolved dependency uri @ refs/tags/v1.0.0 no ref",
			prov: BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						StatementHeader: intoto.StatementHeader{},
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ResolvedDependencies: []slsa1.ResourceDescriptor{
									{
										URI: "git+https://github.com/kubernetes/kubernetes",
									},
								},
							},
						},
					},
				},
			},
			err: serrors.ErrorInvalidDssePayload,
		},
	}

	for i := range testCases {
		tt := testCases[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tag, err := tt.prov.GetTag()
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := tag, tt.tag; got != want {
				t.Fatalf("unexpected tag, got: %q, want: %q", got, want)
			}
		})
	}
}
