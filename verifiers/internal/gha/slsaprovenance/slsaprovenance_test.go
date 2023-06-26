package slsaprovenance

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	intoto_slsav1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	slsav1 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/v1.0"
)

func mustJSON(o any) string {
	b, err := json.Marshal(o)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func Test_ProvenanceFromEnvelope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		envelope *dsse.Envelope
		path     string
		err      error
	}{
		{
			name: "valid dsse",
			envelope: &dsse.Envelope{
				PayloadType: intoto.PayloadType,
				Payload: mustJSON(&slsav1.Attestation{
					StatementHeader: intoto.StatementHeader{
						PredicateType: intoto_slsav1.PredicateSLSAProvenance,
					},
					Predicate: intoto_slsav1.ProvenancePredicate{
						BuildDefinition: intoto_slsav1.ProvenanceBuildDefinition{
							BuildType: slsav1.BYOBBuildType,
						},
					},
				}),
			},
		},
		{
			name: "invalid dsse: not SLSA predicate",
			envelope: &dsse.Envelope{
				PayloadType: intoto.PayloadType,
				Payload: mustJSON(&intoto.StatementHeader{
					// NOTE: Not a SLSA predicate type.
					PredicateType: intoto.PredicateSPDX,
				}),
			},
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "invalid dsse: not base64",
			envelope: &dsse.Envelope{
				PayloadType: intoto.PayloadType,
				// NOTE: Not valid base64.
				Payload: "i&(*$(@&^&)))",
			},
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "invalid dsse: not json",
			envelope: &dsse.Envelope{
				PayloadType: intoto.PayloadType,
				// NOTE: Not valid JSON.
				Payload: base64.StdEncoding.EncodeToString([]byte("{'not valid json'")),
			},
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "invalid dsse: not in-toto",
			envelope: &dsse.Envelope{
				// NOTE: Not an in-toto attestation payload type,
				PayloadType: "http://github.com/other/payload/type",
				// NOTE: The rest of the payload should be valid.
				Payload: mustJSON(&slsav1.Attestation{
					StatementHeader: intoto.StatementHeader{
						PredicateType: intoto_slsav1.PredicateSLSAProvenance,
					},
					Predicate: intoto_slsav1.ProvenancePredicate{
						BuildDefinition: intoto_slsav1.ProvenanceBuildDefinition{
							BuildType: slsav1.BYOBBuildType,
						},
					},
				}),
			},
			err: serrors.ErrorInvalidDssePayload,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ProvenanceFromEnvelope(tt.envelope)
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("unexpected error (-want +got):\n%s", diff)
			}
		})
	}
}
