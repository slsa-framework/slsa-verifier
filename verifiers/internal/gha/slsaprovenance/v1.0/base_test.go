package v1

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
)

type testProvenance struct {
	*provenanceV1
}

var testPath = "./path/to/workflow.yml"

func Test_GetExternalParams(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		prov           testProvenance
		expectedParams map[string]interface{}
		expectedError  error
	}{
		{
			name: "empty build definition",
			prov: testProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{},
						},
					},
				},
			},
			expectedParams: nil,
			expectedError:  serrors.ErrorInvalidDssePayload,
		},
		{
			name: "success: empty external parameters",
			prov: testProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]interface{}{},
							},
						},
					},
				},
			},
			expectedParams: make(map[string]interface{}),
			expectedError:  nil,
		},
		{
			name: "success: non-empty external parameters",
			prov: testProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]interface{}{
									"key": "value",
								},
							},
						},
					},
				},
			},
			expectedParams: map[string]interface{}{
				"key": "value",
			},
			expectedError: nil,
		},
	}
	for i := range testCases {
		tt := testCases[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			params, err := tt.prov.GetExternalParameters()
			if diff := cmp.Diff(tt.expectedError, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(params, tt.expectedParams); diff != "" {
				t.Fatalf("unexpected trigger URI: %s", diff)
			}
		})
	}
}

func Test_GetBuildTriggerPath(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name          string
		prov          iface.Provenance
		expectedPath  string
		expectedError error
	}{
		{
			name: "missing workflow",
			prov: testProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]interface{}{
									"other": map[string]interface{}{},
								},
							},
						},
					},
				},
			},
			expectedPath:  "",
			expectedError: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "workflow as map[string]interface{} missing path",
			prov: testProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]interface{}{
									"workflow": map[string]interface{}{
										"key": "value",
									},
								},
							},
						},
					},
				},
			},
			expectedPath:  "",
			expectedError: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "workflow as map[string]string missing path",
			prov: testProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]interface{}{
									"workflow": map[string]string{
										"key": "value",
									},
								},
							},
						},
					},
				},
			},
			expectedPath:  "",
			expectedError: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "success: workflow as map[string]string",
			prov: testProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]interface{}{
									"workflow": map[string]string{
										"path": testPath,
									},
								},
							},
						},
					},
				},
			},
			expectedPath: testPath,
		},
		{
			name: "success: workflow as map[string]interface{}",
			prov: testProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]interface{}{
									"workflow": map[string]interface{}{
										"path": testPath,
									},
								},
							},
						},
					},
				},
			},
			expectedPath: testPath,
		},
	}
	for i := range testCases {
		tt := testCases[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			triggerPath, err := tt.prov.GetBuildTriggerPath()
			if diff := cmp.Diff(tt.expectedError, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := triggerPath, tt.expectedPath; got != want {
				t.Fatalf("unexpected trigger URI, got: %q, want: %q", got, want)
			}
		})
	}
}
