package gha

import (
	// "fmt"
	// "os"
	"testing"

	"github.com/google/go-cmp/cmp"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	intotocommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	intotov02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	intotov10 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1.0"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	slsav02 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/v0.2"
	slsav10 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/v1.0"
)

func Test_verifySubjectDigestName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		subject    []intoto.Subject
		digestName string
		err        error
	}{
		{
			name:       "valid digest",
			digestName: "sha256",
			subject: []intoto.Subject{
				{
					Digest: intotocommon.DigestSet{"sha256": "abcd"},
				},
			},
		},
		{
			name:       "invalid 2 subjects",
			digestName: "sha256",
			subject: []intoto.Subject{
				{
					Digest: intotocommon.DigestSet{"sha256": "abcd"},
				},
				{
					Digest: intotocommon.DigestSet{"sha256": "abcd"},
				},
			},
			err: serrors.ErrorNonVerifiableClaim,
		},
		{
			name:       "invalid no subjects",
			digestName: "sha256",
			err:        serrors.ErrorInvalidDssePayload,
		},
		{
			name:       "wrong digest",
			digestName: "sha512",
			subject: []intoto.Subject{
				{
					Digest: intotocommon.DigestSet{"sha256": "abcd"},
				},
			},
			err: serrors.ErrorNonVerifiableClaim,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov02 := &slsav02.ProvenanceV02{
				&intoto.ProvenanceStatement{
					StatementHeader: intoto.StatementHeader{
						Subject: tt.subject,
					},
				},
			}
			err := verifySubjectDigestName(prov02, tt.digestName)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}

			prov10 := &slsav10.ProvenanceV1{
				StatementHeader: intoto.StatementHeader{
					Subject: tt.subject,
				},
			}
			err = verifySubjectDigestName(prov10, tt.digestName)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyBuildConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		workflow WorkflowIdentity
		err      error
	}{
		{
			name: "same path",
			path: "the/path",
			workflow: WorkflowIdentity{
				BuildConfigPath: asStringPointer("the/path"),
			},
		},
		{
			name: "no certificate path",
			path: "the/path",
			err:  serrors.ErrorMismatchCertificate,
		},
		{
			name: "different path",
			path: "another/path",
			workflow: WorkflowIdentity{
				BuildConfigPath: asStringPointer("the/path"),
			},
			err: serrors.ErrorMismatchCertificate,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov02 := &slsav02.ProvenanceV02{
				&intoto.ProvenanceStatement{
					Predicate: intotov02.ProvenancePredicate{
						Invocation: intotov02.ProvenanceInvocation{
							ConfigSource: intotov02.ConfigSource{
								EntryPoint: tt.path,
							},
						},
					},
				},
			}
			err := verifyBuildConfig(prov02, &tt.workflow)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}

			prov10 := &slsav10.ProvenanceV1{
				Predicate: intotov10.ProvenancePredicate{
					BuildDefinition: intotov10.ProvenanceBuildDefinition{
						SystemParameters: map[string]interface{}{
							"workflow": map[string]string{
								"path": tt.path,
							},
						},
					},
				},
			}
			err = verifyBuildConfig(prov10, &tt.workflow)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}
