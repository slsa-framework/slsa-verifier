package gha

import (
	"fmt"
	// "os"
	"testing"
	"time"

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

func Test_verifyResolvedDependencies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		n        int
		workflow WorkflowIdentity
		err      error
	}{
		{
			name: "one entry",
			n:    1,
		},
		{
			name: "two entry",
			n:    2,
			err:  serrors.ErrorNonVerifiableClaim,
		},
		{
			name: "no entry",
			n:    0,
			err:  serrors.ErrorNonVerifiableClaim,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov02 := &slsav02.ProvenanceV02{
				&intoto.ProvenanceStatement{
					Predicate: intotov02.ProvenancePredicate{},
				},
			}
			if tt.n > 0 {
				prov02.Predicate.Materials = make([]intotocommon.ProvenanceMaterial, tt.n)
			}
			err := verifyResolvedDependencies(prov02)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}

			prov10 := &slsav10.ProvenanceV1{
				Predicate: intotov10.ProvenancePredicate{
					BuildDefinition: intotov10.ProvenanceBuildDefinition{},
				},
			}
			if tt.n > 0 {
				prov10.Predicate.BuildDefinition.ResolvedDependencies = make([]intotov10.ArtifactReference, tt.n)
			}
			err = verifyResolvedDependencies(prov10)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyCommonMetadata(t *testing.T) {
	t.Parallel()
	now := time.Now()
	tests := []struct {
		name         string
		metadata     bool
		invocationID *string
		startTime    *time.Time
		endTime      *time.Time
		workflow     WorkflowIdentity
		err          error
	}{
		{
			name: "no claims in cert and prov no metadata",
		},
		{
			name:     "no claims in cert and prov with metadata",
			metadata: true,
		},
		{
			name: "invocation ID in cert not in prov no metadata",
			workflow: WorkflowIdentity{
				RunID: asStringPointer("12345/attempt/1"),
			},
		},
		{
			name:     "invocation ID in cert not in prov with metadata",
			metadata: true,
			workflow: WorkflowIdentity{
				RunID: asStringPointer("12345/attempt/1"),
			},
		},
		{
			name:         "invocation ID in cert and prov match",
			invocationID: asStringPointer("12345-1"),
			workflow: WorkflowIdentity{
				RunID: asStringPointer("12345/attempt/1"),
			},
		},
		{
			name:         "invocation ID in cert and prov mismatch attempt",
			invocationID: asStringPointer("12345-2"),
			workflow: WorkflowIdentity{
				RunID: asStringPointer("12345/attempt/1"),
			},
			err: serrors.ErrorMismatchCertificate,
		},
		{
			name:         "invocation ID in cert and prov mismatch run",
			invocationID: asStringPointer("1234-1"),
			workflow: WorkflowIdentity{
				RunID: asStringPointer("12345/attempt/1"),
			},
			err: serrors.ErrorMismatchCertificate,
		},
		{
			name:         "invocation ID in prov only with metadata",
			invocationID: asStringPointer("1234-1"),
			metadata:     true,
			err:          serrors.ErrorMismatchCertificate,
		},
		{
			name:         "invocation ID in prov only no metadata",
			invocationID: asStringPointer("1234-1"),
			err:          serrors.ErrorMismatchCertificate,
		},
		{
			name:      "start time in prov not in cert",
			startTime: &now,
			err:       serrors.ErrorNonVerifiableClaim,
		},
		{
			name:    "end time in prov not in cert",
			endTime: &now,
			err:     serrors.ErrorNonVerifiableClaim,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			metadata := tt.metadata || tt.invocationID != nil || tt.startTime != nil ||
				tt.endTime != nil
			prov02 := &slsav02.ProvenanceV02{
				&intoto.ProvenanceStatement{
					Predicate: intotov02.ProvenancePredicate{},
				},
			}
			if metadata {
				prov02.Predicate.Metadata = &intotov02.ProvenanceMetadata{}
			}
			if tt.invocationID != nil {
				prov02.Predicate.Metadata.BuildInvocationID = *tt.invocationID
			}
			if tt.startTime != nil {
				prov02.Predicate.Metadata.BuildStartedOn = tt.startTime
			}
			if tt.endTime != nil {
				prov02.Predicate.Metadata.BuildFinishedOn = tt.endTime
			}

			err := verifyCommonMetadata(prov02, &tt.workflow)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}

			prov10 := &slsav10.ProvenanceV1{}

			if tt.invocationID != nil {
				prov10.Predicate.RunDetails.BuildMetadata.InvocationID = *tt.invocationID
			}
			if tt.startTime != nil {
				prov10.Predicate.RunDetails.BuildMetadata.StartedOn = tt.startTime
			}
			if tt.endTime != nil {
				prov10.Predicate.RunDetails.BuildMetadata.FinishedOn = tt.endTime
			}

			err = verifyCommonMetadata(prov10, &tt.workflow)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyV02Metadata(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                                             string
		reproducible, parameters, materials, environment bool
		metadata                                         bool
		err                                              error
	}{
		{
			name:     "correct all false",
			metadata: true,
		},
		{
			name:     "no metadata",
			metadata: false,
		},
		{
			name:         "reproducible true",
			reproducible: true,
			err:          serrors.ErrorNonVerifiableClaim,
		},
		{
			name:       "parameters true",
			parameters: true,
			err:        serrors.ErrorNonVerifiableClaim,
		},
		{
			name:      "materials true",
			materials: true,
			err:       serrors.ErrorNonVerifiableClaim,
		},
		{
			name:        "environment true",
			environment: true,
			err:         serrors.ErrorNonVerifiableClaim,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			metadata := tt.metadata || tt.reproducible || tt.parameters ||
				tt.environment || tt.materials

			prov02 := &slsav02.ProvenanceV02{
				&intoto.ProvenanceStatement{},
			}
			if metadata {
				prov02.Predicate.Metadata = &intotov02.ProvenanceMetadata{
					Completeness: intotov02.ProvenanceComplete{
						Parameters:  tt.parameters,
						Materials:   tt.materials,
						Environment: tt.environment,
					},
					Reproducible: tt.reproducible,
				}
			}
			err := verifyV02Metadata(prov02)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyMetadata(t *testing.T) {
	t.Parallel()
	now := time.Now()
	tests := []struct {
		name string
		// These 4 parameters are only present in v0.2 provenance.
		reproducible, parameters, materials, environment bool
		metadata                                         bool
		invocationID                                     *string
		startTime                                        *time.Time
		endTime                                          *time.Time
		workflow                                         WorkflowIdentity
		errV01, errV02                                   error
	}{
		// From Test_verifyV02Metadata.
		{
			name:         "reproducible true",
			reproducible: true,
			errV02:       serrors.ErrorNonVerifiableClaim,
		},
		{
			name:       "parameters true",
			parameters: true,
			errV02:     serrors.ErrorNonVerifiableClaim,
		},
		{
			name:      "materials true",
			materials: true,
			errV02:    serrors.ErrorNonVerifiableClaim,
		},
		{
			name:        "environment true",
			environment: true,
			errV02:      serrors.ErrorNonVerifiableClaim,
		},

		{
			name: "no claims in cert and prov no metadata",
		},
		{
			name:     "no claims in cert and prov with metadata",
			metadata: true,
		},
		// From Test_verifyCommonMetadata.
		{
			name: "invocation ID in cert not in prov no metadata",
			workflow: WorkflowIdentity{
				RunID: asStringPointer("12345/attempt/1"),
			},
		},
		{
			name:     "invocation ID in cert not in prov with metadata",
			metadata: true,
			workflow: WorkflowIdentity{
				RunID: asStringPointer("12345/attempt/1"),
			},
		},
		{
			name:         "invocation ID in cert and prov match",
			invocationID: asStringPointer("12345-1"),
			workflow: WorkflowIdentity{
				RunID: asStringPointer("12345/attempt/1"),
			},
		},
		{
			name:         "invocation ID in cert and prov mismatch attempt",
			invocationID: asStringPointer("12345-2"),
			workflow: WorkflowIdentity{
				RunID: asStringPointer("12345/attempt/1"),
			},
			errV01: serrors.ErrorMismatchCertificate,
			errV02: serrors.ErrorMismatchCertificate,
		},
		{
			name:         "invocation ID in cert and prov mismatch run",
			invocationID: asStringPointer("1234-1"),
			workflow: WorkflowIdentity{
				RunID: asStringPointer("12345/attempt/1"),
			},
			errV01: serrors.ErrorMismatchCertificate,
			errV02: serrors.ErrorMismatchCertificate,
		},
		{
			name:         "invocation ID in prov only with metadata",
			invocationID: asStringPointer("1234-1"),
			metadata:     true,
			errV01:       serrors.ErrorMismatchCertificate,
			errV02:       serrors.ErrorMismatchCertificate,
		},
		{
			name:         "invocation ID in prov only no metadata",
			invocationID: asStringPointer("1234-1"),
			errV01:       serrors.ErrorMismatchCertificate,
			errV02:       serrors.ErrorMismatchCertificate,
		},
		{
			name:      "start time in prov not in cert",
			startTime: &now,
			errV01:    serrors.ErrorNonVerifiableClaim,
			errV02:    serrors.ErrorNonVerifiableClaim,
		},
		{
			name:    "end time in prov not in cert",
			endTime: &now,
			errV01:  serrors.ErrorNonVerifiableClaim,
			errV02:  serrors.ErrorNonVerifiableClaim,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			metadata := tt.metadata || tt.invocationID != nil || tt.startTime != nil ||
				tt.endTime != nil || tt.reproducible || tt.parameters ||
				tt.environment || tt.materials

			prov02 := &slsav02.ProvenanceV02{
				&intoto.ProvenanceStatement{},
			}
			if metadata {
				prov02.Predicate.Metadata = &intotov02.ProvenanceMetadata{
					Completeness: intotov02.ProvenanceComplete{
						Parameters:  tt.parameters,
						Materials:   tt.materials,
						Environment: tt.environment,
					},
					Reproducible: tt.reproducible,
				}
				fmt.Println(prov02.Predicate.Metadata.Reproducible)
				if tt.invocationID != nil {
					prov02.Predicate.Metadata.BuildInvocationID = *tt.invocationID
				}
				if tt.startTime != nil {
					prov02.Predicate.Metadata.BuildStartedOn = tt.startTime
				}
				if tt.endTime != nil {
					prov02.Predicate.Metadata.BuildFinishedOn = tt.endTime
				}
			}
			errV02 := verifyMetadata(prov02, &tt.workflow)
			if !errCmp(errV02, tt.errV02) {
				t.Errorf(cmp.Diff(errV02, tt.errV02))
			}

			prov10 := &slsav10.ProvenanceV1{}

			if tt.invocationID != nil {
				prov10.Predicate.RunDetails.BuildMetadata.InvocationID = *tt.invocationID
			}
			if tt.startTime != nil {
				prov10.Predicate.RunDetails.BuildMetadata.StartedOn = tt.startTime
			}
			if tt.endTime != nil {
				prov10.Predicate.RunDetails.BuildMetadata.FinishedOn = tt.endTime
			}

			errV01 := verifyMetadata(prov10, &tt.workflow)
			if !errCmp(errV01, tt.errV01) {
				t.Errorf(cmp.Diff(errV01, tt.errV01))
			}
		})
	}
}
