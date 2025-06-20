package v1

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

var (
	testProvRepository = "https://github.com/sigstore/sigstore-js"
	testProvRef        = "refs/heads/main"
	testProvTriggerURI = "git+https://github.com/sigstore/sigstore-js@refs/heads/main"
)

func Test_NpmCLIGithubActionsProvenance_TriggerURI(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		prov       NpmCLIGithubActionsProvenance
		triggerURI string
		err        error
	}{
		{
			name: "empty external parameters",
			prov: NpmCLIGithubActionsProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]any{},
							},
						},
					},
				},
			},
			triggerURI: "",
			err:        serrors.ErrorInvalidFormat,
		},
		{
			name: "empty workflow parameters",
			prov: NpmCLIGithubActionsProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]any{
									"workflow": map[string]any{},
								},
							},
						},
					},
				},
			},
			triggerURI: "",
			err:        serrors.ErrorInvalidFormat,
		},
		{
			name: "missing repository parameter",
			prov: NpmCLIGithubActionsProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]any{
									"workflow": map[string]any{
										"ref": testProvRef,
									},
								},
							},
						},
					},
				},
			},
			triggerURI: "",
			err:        serrors.ErrorInvalidFormat,
		},
		{
			name: "missing ref parameter",
			prov: NpmCLIGithubActionsProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]any{
									"workflow": map[string]any{
										"repository": testProvRef,
									},
								},
							},
						},
					},
				},
			},
			triggerURI: "",
			err:        serrors.ErrorInvalidFormat,
		},
		{
			name: "success",
			prov: NpmCLIGithubActionsProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								ExternalParameters: map[string]any{
									"workflow": map[string]any{
										"repository": testProvRepository,
										"ref":        testProvRef,
									},
								},
							},
						},
					},
				},
			},
			triggerURI: testProvTriggerURI,
			err:        nil,
		},
	}

	for i := range testCases {
		tt := testCases[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			triggerURI, err := tt.prov.TriggerURI()
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := triggerURI, tt.triggerURI; got != want {
				t.Fatalf("unexpected trigger URI, got: %q, want: %q", got, want)
			}
		})
	}
}
