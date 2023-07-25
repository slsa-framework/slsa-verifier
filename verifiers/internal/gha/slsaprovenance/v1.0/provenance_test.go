package v1

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
)

func Test_New(t *testing.T) {
	testCases := []struct {
		name      string
		builderID string
		payload   string
		prov      iface.Provenance
		err       error
	}{
		{
			name:      "BYOB build type",
			builderID: common.GenericDelegatorBuilderID,
			payload: fmt.Sprintf(`{
				"predicate": {
					"buildDefinition": {
						"buildType": %q
					}
				}
			}`, common.BYOBBuildTypeV0),
			prov: &BYOBProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								BuildType: common.BYOBBuildTypeV0,
							},
						},
					},
				},
			},
		},
		{
			name:      "Container-based build type",
			builderID: common.ContainerBasedBuilderID,
			payload: fmt.Sprintf(`{
				"predicate": {
					"buildDefinition": {
						"buildType": %q
					}
				}
			}`, common.ContainerBasedBuildTypeV01Draft),
			prov: &ContainerBasedProvenance{
				provenanceV1: &provenanceV1{
					prov: &Attestation{
						Predicate: slsa1.ProvenancePredicate{
							BuildDefinition: slsa1.ProvenanceBuildDefinition{
								BuildType: common.ContainerBasedBuildTypeV01Draft,
							},
						},
					},
				},
			},
		},
		{
			name: "Unknown fields",
			payload: `{
				"predicate": {
					"unknown": "field",
					"buildDefinition": {
						"buildType": "foo"
					}
				}
			}`,
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name:      "Unknown builder ID",
			builderID: "unknown",
			payload: `{
				"predicate": {
					"buildDefinition": {
						"buildType": "foo"
					}
				}
			}`,
			err: serrors.ErrorInvalidBuilderID,
		},
		{
			name:      "Unknown buildType",
			builderID: common.GenericDelegatorBuilderID,
			payload: `{
				"predicate": {
					"buildDefinition": {
						"buildType": "foo"
					}
				}
			}`,
			err: serrors.ErrorInvalidBuildType,
		},
	}

	for i := range testCases {
		tt := testCases[i]
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.builderID, []byte(tt.payload))
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got): \n%s", diff)
			}
			if diff := cmp.Diff(tt.prov, p, cmp.AllowUnexported(provenanceV1{}, BYOBProvenance{}, ContainerBasedProvenance{})); diff != "" {
				t.Fatalf("unexpected result (-want +got): \n%s", diff)
			}
		})
	}
}
