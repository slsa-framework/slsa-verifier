package gha

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	intotocommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	intotov02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func Test_verifyPublishAttestationSubjectDigestName(t *testing.T) {
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
			err:        serrors.ErrorNonVerifiableClaim,
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov := &testProvenance{
				subjects: tt.subject,
			}
			if err := verifyPublishAttestationSubjectDigestName(prov, tt.digestName); !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov := &testProvenance{
				buildTriggerPath: tt.path,
			}
			if err := verifyBuildConfig(prov, &tt.workflow); !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov := &testProvenance{
				noResolvedDeps: tt.n,
			}
			if err := verifyResolvedDependencies(prov); !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov := &testProvenance{}
			if tt.invocationID != nil {
				prov.buildInvocationID = *tt.invocationID
			}
			if tt.startTime != nil {
				prov.buildStartTime = tt.startTime
			}
			if tt.endTime != nil {
				prov.buildFinishTime = tt.endTime
			}

			if err := verifyCommonMetadata(prov, &tt.workflow); !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			metadata := tt.metadata || tt.reproducible || tt.parameters ||
				tt.environment || tt.materials

			prov02 := &testProvenanceV02{}
			if metadata {
				prov02.predicate.Metadata = &intotov02.ProvenanceMetadata{
					Completeness: intotov02.ProvenanceComplete{
						Parameters:  tt.parameters,
						Materials:   tt.materials,
						Environment: tt.environment,
					},
					Reproducible: tt.reproducible,
				}
			}
			if err := verifyV02Metadata(prov02); !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov02 := &testProvenanceV02{}
			if tt.present || len(tt.value) > 0 {
				prov02.predicate.Invocation.Parameters = tt.value
			}
			err := verifyV02Parameters(prov02)
			if !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov02 := &testProvenanceV02{}
			if tt.present || len(tt.value) > 0 {
				prov02.predicate.BuildConfig = tt.value
			}
			err := verifyV02BuildConfig(prov02)
			if !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov02 := &testProvenanceV02{}
			if tt.invocationID != nil {
				prov02.buildInvocationID = *tt.invocationID
			}
			if tt.startTime != nil {
				prov02.buildStartTime = tt.startTime
			}
			if tt.endTime != nil {
				prov02.buildFinishTime = tt.endTime
			}

			prov02.predicate.Metadata = &intotov02.ProvenanceMetadata{
				Completeness: intotov02.ProvenanceComplete{
					Parameters:  tt.parameters,
					Materials:   tt.materials,
					Environment: tt.environment,
				},
				Reproducible: tt.reproducible,
			}

			if err := verifyMetadata(prov02, &tt.workflow); !errCmp(err, tt.errV02) {
				t.Error(cmp.Diff(err, tt.errV02))
			}

			prov1 := &testProvenanceV1{}
			if tt.invocationID != nil {
				prov1.buildInvocationID = *tt.invocationID
			}
			if tt.startTime != nil {
				prov1.buildStartTime = tt.startTime
			}
			if tt.endTime != nil {
				prov1.buildFinishTime = tt.endTime
			}

			if err := verifyMetadata(prov1, &tt.workflow); !errCmp(err, tt.errV01) {
				t.Error(cmp.Diff(err, tt.errV01))
			}
		})
	}
}

func Test_verifySystemParameters(t *testing.T) {
	t.Parallel()
	expectedWorkflow := WorkflowIdentity{
		BuildTrigger:     "workflow_dispatch",
		SubjectWorkflow:  Must(url.Parse(httpsGithubCom + "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main")),
		SubjectSha1:      asStringPointer("b38894f2dda4355ea5606fccb166e61565e12a14"),
		SourceRepository: "laurentsimon/provenance-npm-test",
		SourceRef:        asStringPointer("refs/heads/main"),
		SourceID:         asStringPointer("602223945"),
		SourceOwnerID:    asStringPointer("64505099"),
		SourceSha1:       "b38894f2dda4355ea5606fccb166e61565e12a14",
		RunID:            asStringPointer("4757060009/attempt/1"),
	}
	tests := []struct {
		name        string
		environment map[string]any
		workflow    WorkflowIdentity
		err         error
	}{
		{
			name: "all field populated",
			environment: map[string]any{
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
			environment: map[string]any{
				"SOMETHING": "workflow_dispatch",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		// Correct partial populated fields.
		{
			name: "only GITHUB_EVENT_NAME field populated",
			environment: map[string]any{
				"GITHUB_EVENT_NAME": "workflow_dispatch",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_REF field populated",
			environment: map[string]any{
				"GITHUB_REF": "refs/heads/main",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_REPOSITORY field populated",
			environment: map[string]any{
				"GITHUB_REPOSITORY": "laurentsimon/provenance-npm-test",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_REPOSITORY_ID field populated",
			environment: map[string]any{
				"GITHUB_REPOSITORY_ID": "602223945",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_REPOSITORY_OWNER_ID field populated",
			environment: map[string]any{
				"GITHUB_REPOSITORY_OWNER_ID": "64505099",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_RUN_ATTEMPT field populated",
			environment: map[string]any{
				"GITHUB_RUN_ATTEMPT": "1",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_RUN_ID field populated",
			environment: map[string]any{
				"GITHUB_RUN_ID": "4757060009",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_SHA field populated",
			environment: map[string]any{
				"GITHUB_SHA": "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_WORKFLOW_REF field populated",
			environment: map[string]any{
				"GITHUB_WORKFLOW_REF": "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
			},
			workflow: expectedWorkflow,
		},
		{
			name: "only GITHUB_WORKFLOW_SHA field populated",
			environment: map[string]any{
				"GITHUB_WORKFLOW_SHA": "b38894f2dda4355ea5606fccb166e61565e12a14",
			},
			workflow: expectedWorkflow,
		},
		// All fields populated one mismatch.
		{
			name: "GITHUB_EVENT_NAME mismatch",
			environment: map[string]any{
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
			environment: map[string]any{
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
			environment: map[string]any{
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
			environment: map[string]any{
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
			environment: map[string]any{
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
			environment: map[string]any{
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
			environment: map[string]any{
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
			environment: map[string]any{
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
			environment: map[string]any{
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
			environment: map[string]any{
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
			environment: map[string]any{
				"GITHUB_EVENT_NAME": "workflow_dispatch2",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_REF field populated",
			environment: map[string]any{
				"GITHUB_REF": "refs/heads/main2",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_REPOSITORY field populated",
			environment: map[string]any{
				"GITHUB_REPOSITORY": "laurentsimon/provenance-npm-test2",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_REPOSITORY_ID field populated",
			environment: map[string]any{
				"GITHUB_REPOSITORY_ID": "6022239452",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_REPOSITORY_OWNER_ID field populated",
			environment: map[string]any{
				"GITHUB_REPOSITORY_OWNER_ID": "645050992",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_RUN_ATTEMPT field populated",
			environment: map[string]any{
				"GITHUB_RUN_ATTEMPT": "12",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_RUN_ID field populated",
			environment: map[string]any{
				"GITHUB_RUN_ID": "47570600092",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_SHA field populated",
			environment: map[string]any{
				"GITHUB_SHA": "b38894f2dda4355ea5606fccb166e61565e12a142",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_WORKFLOW_REF field populated",
			environment: map[string]any{
				"GITHUB_WORKFLOW_REF": "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main2",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
		{
			name: "incorrect only GITHUB_WORKFLOW_SHA field populated",
			environment: map[string]any{
				"GITHUB_WORKFLOW_SHA": "b38894f2dda4355ea5606fccb166e61565e12a142",
			},
			workflow: expectedWorkflow,
			err:      serrors.ErrorMismatchCertificate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov := &testProvenance{
				systemParameters: tt.environment,
			}

			if err := verifySystemParameters(prov, &tt.workflow); !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyProvenanceMatchesCertificate(t *testing.T) {
	t.Parallel()
	expectedWorkflow := WorkflowIdentity{
		BuildTrigger:     "workflow_dispatch",
		BuildConfigPath:  asStringPointer("release/workflow/path"),
		SubjectWorkflow:  Must(url.Parse(httpsGithubCom + "repo/name/release/workflow/path@subject-ref")),
		SubjectSha1:      asStringPointer("subject-sha"),
		SourceRepository: "repo/name",
		SourceRef:        asStringPointer("source-ref"),
		SourceID:         asStringPointer("source-id"),
		SourceOwnerID:    asStringPointer("source-owner-id"),
		SourceSha1:       "source-sha",
		RunID:            asStringPointer("run-id/attempt/run-attempt"),
	}
	tests := []struct {
		name                       string
		subject                    []intoto.Subject
		numberResolvedDependencies int
		workflowTriggerPath        string
		environment                map[string]any
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
			environment: map[string]any{
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
			subject: []intoto.Subject{
				{
					Digest: intotocommon.DigestSet{"sha512": "abcd"},
				},
			},
			environment: map[string]any{
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
			environment: map[string]any{
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
			environment: map[string]any{
				"GITHUB_EVENT_NAME": "workflow_dispatch2",
			},
			certificateIdentity: expectedWorkflow,
			err:                 serrors.ErrorMismatchCertificate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov := &testProvenance{
				subjects:         tt.subject,
				noResolvedDeps:   tt.numberResolvedDependencies,
				buildTriggerPath: tt.workflowTriggerPath,
				systemParameters: tt.environment,
			}

			if err := verifyProvenanceMatchesCertificate(prov, &tt.certificateIdentity); !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
			}
		})
	}
}
