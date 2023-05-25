package gha

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	intotocommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	intotov02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	intotov1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
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

			prov1 := &slsav10.ProvenanceV1{
				StatementHeader: intoto.StatementHeader{
					Subject: tt.subject,
				},
			}
			err = verifySubjectDigestName(prov1, tt.digestName)
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

			prov1 := &slsav10.ProvenanceV1{
				Predicate: intotov1.ProvenancePredicate{
					BuildDefinition: intotov1.ProvenanceBuildDefinition{
						InternalParameters: map[string]interface{}{
							"GITHUB_WORKFLOW_REF": fmt.Sprintf("some/repo/%s@some-ref", tt.path),
						},
					},
				},
			}
			err = verifyBuildConfig(prov1, &tt.workflow)
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

			prov1 := &slsav10.ProvenanceV1{
				Predicate: intotov1.ProvenancePredicate{
					BuildDefinition: intotov1.ProvenanceBuildDefinition{},
				},
			}
			if tt.n > 0 {
				prov1.Predicate.BuildDefinition.ResolvedDependencies = make([]intotov1.ResourceDescriptor, tt.n)
			}
			err = verifyResolvedDependencies(prov1)
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

			prov1 := &slsav10.ProvenanceV1{}

			if tt.invocationID != nil {
				prov1.Predicate.RunDetails.BuildMetadata.InvocationID = *tt.invocationID
			}
			if tt.startTime != nil {
				prov1.Predicate.RunDetails.BuildMetadata.StartedOn = tt.startTime
			}
			if tt.endTime != nil {
				prov1.Predicate.RunDetails.BuildMetadata.FinishedOn = tt.endTime
			}

			err = verifyCommonMetadata(prov1, &tt.workflow)
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

func Test_verifyV02Parameters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		present bool
		value   map[string]any
		err     error
	}{
		{
			name: "no parameters",
		},
		{
			name:    "empty parameters",
			present: true,
		},
		{
			name:  "0-length parameters",
			value: make(map[string]any, 0),
		},
		{
			name:  "non-empty no parameters",
			value: make(map[string]any, 1),
		},
		{
			name:  "non-empty with parameters",
			value: map[string]any{"param": "val"},
			err:   serrors.ErrorNonVerifiableClaim,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov02 := &slsav02.ProvenanceV02{
				&intoto.ProvenanceStatement{},
			}
			if tt.present || len(tt.value) > 0 {
				prov02.Predicate.Invocation.Parameters = tt.value
			}
			err := verifyV02Parameters(prov02)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyV02BuildConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		present bool
		value   map[string]any
		err     error
	}{
		{
			name: "no parameters",
		},
		{
			name:    "empty parameters",
			present: true,
		},
		{
			name:  "0-length parameters",
			value: make(map[string]any, 0),
		},
		{
			name:  "non-empty no parameters",
			value: make(map[string]any, 1),
		},
		{
			name:  "non-empty with parameters",
			value: map[string]any{"param": "val"},
			err:   serrors.ErrorNonVerifiableClaim,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov02 := &slsav02.ProvenanceV02{
				&intoto.ProvenanceStatement{},
			}
			if tt.present || len(tt.value) > 0 {
				prov02.Predicate.BuildConfig = tt.value
			}
			err := verifyV02BuildConfig(prov02)
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

			prov1 := &slsav10.ProvenanceV1{}

			if tt.invocationID != nil {
				prov1.Predicate.RunDetails.BuildMetadata.InvocationID = *tt.invocationID
			}
			if tt.startTime != nil {
				prov1.Predicate.RunDetails.BuildMetadata.StartedOn = tt.startTime
			}
			if tt.endTime != nil {
				prov1.Predicate.RunDetails.BuildMetadata.FinishedOn = tt.endTime
			}

			errV01 := verifyMetadata(prov1, &tt.workflow)
			if !errCmp(errV01, tt.errV01) {
				t.Errorf(cmp.Diff(errV01, tt.errV01))
			}
		})
	}
}

func Test_verifySystemParameters(t *testing.T) {
	t.Parallel()
	expectedWorkflow := WorkflowIdentity{
		BuildTrigger:       "workflow_dispatch",
		SubjectWorkflowRef: "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
		SubjectSha1:        asStringPointer("b38894f2dda4355ea5606fccb166e61565e12a14"),
		SourceRepository:   "laurentsimon/provenance-npm-test",
		SourceRef:          asStringPointer("refs/heads/main"),
		SourceID:           asStringPointer("602223945"),
		SourceOwnerID:      asStringPointer("64505099"),
		SourceSha1:         "b38894f2dda4355ea5606fccb166e61565e12a14",
		RunID:              asStringPointer("4757060009/attempt/1"),
	}
	tests := []struct {
		name        string
		environment map[string]interface{}
		workflow    WorkflowIdentity
		err         error
	}{
		{
			name: "all field populated",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "refs/heads/main",
				"GITHUB_REPOSITORY":          "laurentsimon/provenance-npm-test",
				"GITHUB_REPOSITORY_ID":       "602223945",
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
				"GITHUB_RUN_ATTEMPT":         "1",
				"GITHUB_RUN_ID":              "4757060009",
				"GITHUB_SHA":                 "b38894f2dda4355ea5606fccb166e61565e12a14",
				"GITHUB_WORKFLOW_REF":        "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
				"GITHUB_WORKFLOW_SHA":        "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "unknown field",
			environment: map[string]interface{}{
				"SOMETHING": "workflow_dispatch",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		// Correct partial populated fields.
		{
			name: "only GITHUB_EVENT_NAME field populated",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME": "workflow_dispatch",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_REF field populated",
			environment: map[string]interface{}{
				"GITHUB_REF": "refs/heads/main",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_REPOSITORY field populated",
			environment: map[string]interface{}{
				"GITHUB_REPOSITORY": "laurentsimon/provenance-npm-test",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_REPOSITORY_ID field populated",
			environment: map[string]interface{}{
				"GITHUB_REPOSITORY_ID": "602223945",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_REPOSITORY_OWNER_ID field populated",
			environment: map[string]interface{}{
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_RUN_ATTEMPT field populated",
			environment: map[string]interface{}{
				"GITHUB_RUN_ATTEMPT": "1",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_RUN_ID field populated",
			environment: map[string]interface{}{
				"GITHUB_RUN_ID": "4757060009",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_SHA field populated",
			environment: map[string]interface{}{
				"GITHUB_SHA": "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_WORKFLOW_REF field populated",
			environment: map[string]interface{}{
				"GITHUB_WORKFLOW_REF": "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_WORKFLOW_SHA field populated",
			environment: map[string]interface{}{
				"GITHUB_WORKFLOW_SHA": "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
		},
		// All fields populated one mismatch.
		{
			name: "GITHUB_EVENT_NAME mismatch",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch2",
				"GITHUB_REF":                 "refs/heads/main",
				"GITHUB_REPOSITORY":          "laurentsimon/provenance-npm-test",
				"GITHUB_REPOSITORY_ID":       "602223945",
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
				"GITHUB_RUN_ATTEMPT":         "1",
				"GITHUB_RUN_ID":              "4757060009",
				"GITHUB_SHA":                 "b38894f2dda4355ea5606fccb166e61565e12a14",
				"GITHUB_WORKFLOW_REF":        "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
				"GITHUB_WORKFLOW_SHA":        "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "GITHUB_REF mismatch",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "refs/heads/main2",
				"GITHUB_REPOSITORY":          "laurentsimon/provenance-npm-test",
				"GITHUB_REPOSITORY_ID":       "602223945",
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
				"GITHUB_RUN_ATTEMPT":         "1",
				"GITHUB_RUN_ID":              "4757060009",
				"GITHUB_SHA":                 "b38894f2dda4355ea5606fccb166e61565e12a14",
				"GITHUB_WORKFLOW_REF":        "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
				"GITHUB_WORKFLOW_SHA":        "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "GITHUB_REPOSITORY mismatch",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "refs/heads/main",
				"GITHUB_REPOSITORY":          "laurentsimon/provenance-npm-test2",
				"GITHUB_REPOSITORY_ID":       "602223945",
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
				"GITHUB_RUN_ATTEMPT":         "1",
				"GITHUB_RUN_ID":              "4757060009",
				"GITHUB_SHA":                 "b38894f2dda4355ea5606fccb166e61565e12a14",
				"GITHUB_WORKFLOW_REF":        "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
				"GITHUB_WORKFLOW_SHA":        "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "GITHUB_REPOSITORY_ID mismatch",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "refs/heads/main",
				"GITHUB_REPOSITORY":          "laurentsimon/provenance-npm-test",
				"GITHUB_REPOSITORY_ID":       "6022239452",
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
				"GITHUB_RUN_ATTEMPT":         "1",
				"GITHUB_RUN_ID":              "4757060009",
				"GITHUB_SHA":                 "b38894f2dda4355ea5606fccb166e61565e12a14",
				"GITHUB_WORKFLOW_REF":        "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
				"GITHUB_WORKFLOW_SHA":        "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "GITHUB_REPOSITORY_OWNER_ID mismatch",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "refs/heads/main",
				"GITHUB_REPOSITORY":          "laurentsimon/provenance-npm-test",
				"GITHUB_REPOSITORY_ID":       "602223945",
				"GITHUB_REPOSITORY_OWNER_ID": "645050992",
				"GITHUB_RUN_ATTEMPT":         "1",
				"GITHUB_RUN_ID":              "4757060009",
				"GITHUB_SHA":                 "b38894f2dda4355ea5606fccb166e61565e12a14",
				"GITHUB_WORKFLOW_REF":        "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
				"GITHUB_WORKFLOW_SHA":        "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "GITHUB_RUN_ATTEMPT mismatch",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "refs/heads/main",
				"GITHUB_REPOSITORY":          "laurentsimon/provenance-npm-test",
				"GITHUB_REPOSITORY_ID":       "602223945",
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
				"GITHUB_RUN_ATTEMPT":         "12",
				"GITHUB_RUN_ID":              "4757060009",
				"GITHUB_SHA":                 "b38894f2dda4355ea5606fccb166e61565e12a14",
				"GITHUB_WORKFLOW_REF":        "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
				"GITHUB_WORKFLOW_SHA":        "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "GITHUB_RUN_ID mismatch",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "refs/heads/main",
				"GITHUB_REPOSITORY":          "laurentsimon/provenance-npm-test",
				"GITHUB_REPOSITORY_ID":       "602223945",
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
				"GITHUB_RUN_ATTEMPT":         "1",
				"GITHUB_RUN_ID":              "47570600092",
				"GITHUB_SHA":                 "b38894f2dda4355ea5606fccb166e61565e12a14",
				"GITHUB_WORKFLOW_REF":        "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
				"GITHUB_WORKFLOW_SHA":        "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "GITHUB_SHA mismatch",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "refs/heads/main",
				"GITHUB_REPOSITORY":          "laurentsimon/provenance-npm-test",
				"GITHUB_REPOSITORY_ID":       "602223945",
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
				"GITHUB_RUN_ATTEMPT":         "1",
				"GITHUB_RUN_ID":              "4757060009",
				"GITHUB_SHA":                 "b38894f2dda4355ea5606fccb166e61565e12a142",
				"GITHUB_WORKFLOW_REF":        "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
				"GITHUB_WORKFLOW_SHA":        "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "GITHUB_WORKFLOW_REF mismatch",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "refs/heads/main",
				"GITHUB_REPOSITORY":          "laurentsimon/provenance-npm-test",
				"GITHUB_REPOSITORY_ID":       "602223945",
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
				"GITHUB_RUN_ATTEMPT":         "1",
				"GITHUB_RUN_ID":              "4757060009",
				"GITHUB_SHA":                 "b38894f2dda4355ea5606fccb166e61565e12a14",
				"GITHUB_WORKFLOW_REF":        "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main2",
				"GITHUB_WORKFLOW_SHA":        "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "GITHUB_WORKFLOW_SHA mismatch",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "refs/heads/main",
				"GITHUB_REPOSITORY":          "laurentsimon/provenance-npm-test",
				"GITHUB_REPOSITORY_ID":       "602223945",
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
				"GITHUB_RUN_ATTEMPT":         "1",
				"GITHUB_RUN_ID":              "4757060009",
				"GITHUB_SHA":                 "b38894f2dda4355ea5606fccb166e61565e12a14",
				"GITHUB_WORKFLOW_REF":        "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
				"GITHUB_WORKFLOW_SHA":        "b38894f2dda4355ea5606fccb166e61565e12a142",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		// Incorrect partially populated fields.
		{
			name: "incorrect only GITHUB_EVENT_NAME field populated",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME": "workflow_dispatch2",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_REF field populated",
			environment: map[string]interface{}{
				"GITHUB_REF": "refs/heads/main2",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_REPOSITORY field populated",
			environment: map[string]interface{}{
				"GITHUB_REPOSITORY": "laurentsimon/provenance-npm-test2",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_REPOSITORY_ID field populated",
			environment: map[string]interface{}{
				"GITHUB_REPOSITORY_ID": "6022239452",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_REPOSITORY_OWNER_ID field populated",
			environment: map[string]interface{}{
				"GITHUB_REPOSITORY_OWNER_ID": "645050992",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_RUN_ATTEMPT field populated",
			environment: map[string]interface{}{
				"GITHUB_RUN_ATTEMPT": "12",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_RUN_ID field populated",
			environment: map[string]interface{}{
				"GITHUB_RUN_ID": "47570600092",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_SHA field populated",
			environment: map[string]interface{}{
				"GITHUB_SHA": "b38894f2dda4355ea5606fccb166e61565e12a142",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_WORKFLOW_REF field populated",
			environment: map[string]interface{}{
				"GITHUB_WORKFLOW_REF": "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main2",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_WORKFLOW_SHA field populated",
			environment: map[string]interface{}{
				"GITHUB_WORKFLOW_SHA": "b38894f2dda4355ea5606fccb166e61565e12a142",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
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
							Environment: tt.environment,
						},
					},
				},
			}

			err := verifySystemParameters(prov02, &tt.workflow)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}

			prov1 := &slsav10.ProvenanceV1{
				Predicate: intotov1.ProvenancePredicate{
					BuildDefinition: intotov1.ProvenanceBuildDefinition{
						InternalParameters: tt.environment,
					},
				},
			}
			err = verifySystemParameters(prov1, &tt.workflow)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyProvenanceMatchesCertificate(t *testing.T) {
	t.Parallel()
	expectedWorkflow := WorkflowIdentity{
		BuildTrigger:       "workflow_dispatch",
		BuildConfigPath:    asStringPointer("release/workflow/path"),
		SubjectWorkflowRef: "repo/name/release/workflow/path@subject-ref",
		SubjectSha1:        asStringPointer("subject-sha"),
		SourceRepository:   "repo/name",
		SourceRef:          asStringPointer("source-ref"),
		SourceID:           asStringPointer("source-id"),
		SourceOwnerID:      asStringPointer("source-owner-id"),
		SourceSha1:         "source-sha",
		RunID:              asStringPointer("run-id/attempt/run-attempt"),
	}
	tests := []struct {
		name                       string
		subject                    []intoto.Subject
		numberResolvedDependencies int
		workflowTriggerPath        string
		environment                map[string]interface{}
		certificateIdentity        WorkflowIdentity
		err                        error
	}{
		{
			name: "correct provenance",
			subject: []intoto.Subject{
				{
					Digest: intotocommon.DigestSet{"sha512": "abcd"},
				},
			},
			numberResolvedDependencies: 1,
			workflowTriggerPath:        "release/workflow/path",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "source-ref",
				"GITHUB_REPOSITORY":          "repo/name",
				"GITHUB_REPOSITORY_ID":       "source-id",
				"GITHUB_REPOSITORY_OWNER_ID": "source-owner-id",
				"GITHUB_RUN_ATTEMPT":         "run-attempt",
				"GITHUB_RUN_ID":              "run-id",
				"GITHUB_SHA":                 "source-sha",
				"GITHUB_WORKFLOW_REF":        "repo/name/release/workflow/path@subject-ref",
				"GITHUB_WORKFLOW_SHA":        "subject-sha",
			},
			certificateIdentity: expectedWorkflow,
		},
		{
			name: "correct provenance no env",
			subject: []intoto.Subject{
				{
					Digest: intotocommon.DigestSet{"sha512": "abcd"},
				},
			},
			numberResolvedDependencies: 1,
			workflowTriggerPath:        "release/workflow/path",
			certificateIdentity:        expectedWorkflow,
		},
		{
			name: "unknown field",
			environment: map[string]interface{}{
				"SOMETHING": "workflow_dispatch",
			},
			certificateIdentity: expectedWorkflow,
			err:                 serrors.ErrorMismatchCertificate,
		},
		{
			name: "too many resolved dependencies",
			subject: []intoto.Subject{
				{
					Digest: intotocommon.DigestSet{"sha512": "abcd"},
				},
			},
			numberResolvedDependencies: 2,
			workflowTriggerPath:        "release/workflow/path",
			certificateIdentity:        expectedWorkflow,
			err:                        serrors.ErrorNonVerifiableClaim,
		},
		{
			name: "incorrect digest name",
			subject: []intoto.Subject{
				{
					Digest: intotocommon.DigestSet{"sha256": "abcd"},
				},
			},
			numberResolvedDependencies: 1,
			workflowTriggerPath:        "release/workflow/path",
			certificateIdentity:        expectedWorkflow,
			err:                        serrors.ErrorNonVerifiableClaim,
		},
		{
			name: "invalid trigger path",
			subject: []intoto.Subject{
				{
					Digest: intotocommon.DigestSet{"sha512": "abcd"},
				},
			},
			numberResolvedDependencies: 1,
			workflowTriggerPath:        "release/workflow/path2",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME":          "workflow_dispatch",
				"GITHUB_REF":                 "source-ref",
				"GITHUB_REPOSITORY":          "repo/name",
				"GITHUB_REPOSITORY_ID":       "source-id",
				"GITHUB_REPOSITORY_OWNER_ID": "source-owner-id",
				"GITHUB_RUN_ATTEMPT":         "run-attempt",
				"GITHUB_RUN_ID":              "run-id",
				"GITHUB_SHA":                 "source-sha",
				"GITHUB_WORKFLOW_REF":        "repo/name/release/workflow/path2@subject-ref",
				"GITHUB_WORKFLOW_SHA":        "subject-sha",
			},
			certificateIdentity: expectedWorkflow,
			err:                 serrors.ErrorMismatchCertificate,
		},
		{
			name: "invalid trigger name",
			subject: []intoto.Subject{
				{
					Digest: intotocommon.DigestSet{"sha512": "abcd"},
				},
			},
			numberResolvedDependencies: 1,
			workflowTriggerPath:        "release/workflow/path",
			environment: map[string]interface{}{
				"GITHUB_EVENT_NAME": "workflow_dispatch2",
			},
			certificateIdentity: expectedWorkflow,
			err:                 serrors.ErrorMismatchCertificate,
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
					Predicate: intotov02.ProvenancePredicate{
						Invocation: intotov02.ProvenanceInvocation{
							Environment: tt.environment,
							ConfigSource: intotov02.ConfigSource{
								EntryPoint: tt.workflowTriggerPath,
							},
						},
					},
				},
			}

			if tt.numberResolvedDependencies > 0 {
				prov02.Predicate.Materials = make([]intotocommon.ProvenanceMaterial, tt.numberResolvedDependencies)
			}

			err := verifyProvenanceMatchesCertificate(prov02, &tt.certificateIdentity)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}

			prov1 := &slsav10.ProvenanceV1{
				StatementHeader: intoto.StatementHeader{
					Subject: tt.subject,
				},
				Predicate: intotov1.ProvenancePredicate{
					BuildDefinition: intotov1.ProvenanceBuildDefinition{
						InternalParameters: tt.environment,
						// TODO(#566): verify fields for v1.0 provenance.
					},
				},
			}

			if tt.numberResolvedDependencies > 0 {
				prov1.Predicate.BuildDefinition.ResolvedDependencies = make([]intotov1.ResourceDescriptor, tt.numberResolvedDependencies)
			}
			err = verifyProvenanceMatchesCertificate(prov1, &tt.certificateIdentity)
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}
