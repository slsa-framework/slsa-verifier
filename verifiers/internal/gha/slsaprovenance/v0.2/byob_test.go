package v02

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsacommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func Test_byobProvenance_GetBranch(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		prov   *byobProvenance
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
			name: "resolved dependency uri @ refs/heads/main",
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
			name: "internalParameters uri @ refs/heads/main",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]interface{}{
								"GITHUB_REF_TYPE": "branch",
								"GITHUB_REF":      "refs/heads/main",
							},
						},
					},
				},
			),
			branch: "refs/heads/main",
		},
		{
			name: "resolved dependency uri @ refs/tags/v1.0.0",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]interface{}{
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
			name: "internalParameters uri @ ref/tags/v1.0.0",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]interface{}{
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
			branch: "",
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
		prov *byobProvenance
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
			name: "resolved dependency uri @ refs/heads/main",
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
			name: "internalParameters uri @ refs/heads/main",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]interface{}{
								"GITHUB_REF_TYPE": "branch",
								"GITHUB_REF":      "refs/heads/main",
							},
						},
					},
				},
			),
			tag: "",
		},
		{
			name: "resolved dependency uri @ refs/tags/v1.0.0",
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
			name: "internalParameters uri @ ref/tags/v1.0.0",
			prov: newBYOBProvenance(
				&Attestation{
					StatementHeader: intoto.StatementHeader{},
					Predicate: slsa02.ProvenancePredicate{
						Invocation: slsa02.ProvenanceInvocation{
							Environment: map[string]interface{}{
								"GITHUB_REF_TYPE": "tag",
								"GITHUB_REF":      "refs/tags/v1.0.0",
							},
						},
					},
				},
			),
			tag: "refs/tags/v1.0.0",
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
