package v02

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsacommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
)

func Test_byobProvenance_GetBranch(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		prov   iface.Provenance
		branch string
		err    error
	}{
		{
			name: "empty provenance",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate:       slsa02.ProvenancePredicate{},
				},
			),
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "materials uri @ refs/heads/main",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Materials: []slsacommon.ProvenanceMaterial{
							{
								URI: "git+https://github.com/kubernetes/kubernetes@refs/heads/main",
							},
						},
					},
				},
			),
			branch: "refs/heads/main",
		},
		{
			name: "environment GITHUB_REF @ refs/heads/main",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]any{
								"GITHUB_REF_TYPE": "branch",
								"GITHUB_REF":      "refs/heads/main",
							},
						},
					},
				},
			),
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "materials uri @ refs/tags/v1.0.0",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]any{
								"GITHUB_BASE_REF":   "",
								"GITHUB_REF_TYPE":   "tag",
								"GITHUB_REF":        "refs/tags/v1.0.0",
								"GITHUB_EVENT_NAME": "push",
								"GITHUB_EVENT_PAYLOAD": map[string]any{
									"base_ref": nil,
								},
							},
						},
						Materials: []slsacommon.ProvenanceMaterial{
							{
								URI: "git+https://github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
							},
						},
					},
				},
			),
			branch: "",
		},
		{
			name: "environment GITHUB_REF @ ref/tags/v1.0.0",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]any{
								"GITHUB_BASE_REF":   "",
								"GITHUB_REF_TYPE":   "tag",
								"GITHUB_REF":        "refs/tags/v1.0.0",
								"GITHUB_EVENT_NAME": "push",
								"GITHUB_EVENT_PAYLOAD": map[string]any{
									"base_ref": nil,
								},
							},
						},
					},
				},
			),
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "materials uri no ref",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]any{
								"GITHUB_REF_TYPE": "branch",
								"GITHUB_REF":      "refs/heads/main",
							},
						},
						Materials: []slsacommon.ProvenanceMaterial{
							{
								URI: "git+https://github.com/kubernetes/kubernetes",
							},
						},
					},
				},
			),
			err: serrors.ErrorInvalidDssePayload,
		},
	}

	for i := range testCases {
		tt := testCases[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			branch, err := tt.prov.GetBranch()
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := branch, tt.branch; got != want {
				t.Fatalf("unexpected branch, got: %q, want: %q", got, want)
			}
		})
	}
}

func Test_byobProvenance_GetTag(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		prov iface.Provenance
		tag  string
		err  error
	}{
		{
			name: "empty provenance",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate:       slsa02.ProvenancePredicate{},
				},
			),
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "materials uri @ refs/heads/main",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Materials: []slsacommon.ProvenanceMaterial{
							{
								URI: "git+https://github.com/kubernetes/kubernetes@refs/heads/main",
							},
						},
					},
				},
			),
			tag: "",
		},
		{
			name: "environment GITHUB_REF @ refs/heads/main",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]any{
								"GITHUB_REF_TYPE": "branch",
								"GITHUB_REF":      "refs/heads/main",
							},
						},
					},
				},
			),
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "materials uri @ refs/tags/v1.0.0",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Materials: []slsacommon.ProvenanceMaterial{
							{
								URI: "git+https://github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
							},
						},
					},
				},
			),
			tag: "refs/tags/v1.0.0",
		},
		{
			name: "environment GITHUB_REF @ ref/tags/v1.0.0",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]any{
								"GITHUB_REF_TYPE": "tag",
								"GITHUB_REF":      "refs/tags/v1.0.0",
							},
						},
					},
				},
			),
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "materials uri no ref",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]any{
								"GITHUB_REF_TYPE": "tag",
								"GITHUB_REF":      "refs/tags/v1.0.0",
							},
						},
						Materials: []slsacommon.ProvenanceMaterial{
							{
								URI: "git+https://github.com/kubernetes/kubernetes",
							},
						},
					},
				},
			),
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
