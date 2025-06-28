package gha

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/slsa-framework/slsa-verifier/v2/options"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

var (
	mismatchProvenancePredicates = map[string]bool{
		common.ProvenanceV02Type + "a": true,
		common.ProvenanceV1Type + "a":  true,
	}
	mismatchPublishPredicates = map[string]bool{
		publishAttestationV01 + "a": true,
	}
	clientOpts *options.ClientOpts
)

// TestMain intercepts the test runner to run some setup code before running the tests.
func TestMain(m *testing.M) {
	// Initialize the default ClientOpts for parallel tests
	var err error
	clientOpts, err = options.NewDefaultClientOpts()
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func Test_verifyName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		actual   string
		expected string
		err      error
	}{
		{
			name:     "scoped with version same",
			actual:   "@laurentsimon/provenance-npm-test@1.0.0",
			expected: "@laurentsimon/provenance-npm-test",
		},
		{
			name:     "scoped no version same",
			actual:   "@laurentsimon/provenance-npm-test",
			expected: "@laurentsimon/provenance-npm-test",
		},
		{
			name:     "scoped with version different",
			actual:   "@laurentsimon/provenance-npm-test@1.0.0",
			expected: "@laurentsimon/provenance-npm-tes",
			err:      serrors.ErrorMismatchPackageName,
		},
		{
			name:     "scoped not same 1",
			actual:   "@laurentsimon/provenance-npm-test",
			expected: "@aurentsimon/provenance-npm-test",
			err:      serrors.ErrorMismatchPackageName,
		},
		{
			name:     "scoped not same 2",
			actual:   "@laurentsimon/provenance-npm-test",
			expected: "@laurentsimon/provenance-npm-tes",
			err:      serrors.ErrorMismatchPackageName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := verifyName(tt.actual, tt.expected)

			if !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.expected))
			}
		})
	}
}

func Test_verifyPublishSubjectVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		att     *SignedAttestation
		version string
		err     error
	}{
		{
			name: "correct version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
					  "predicate": {
						"name": "@laurentsimon/provenance-npm-test",
						"version": "1.0.0",
						"registry": "https://registry.npmjs.org"
					  }
					}`)),
				},
			},
			version: "1.0.0",
		},
		{
			name: "incorrect subset version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
					  "predicate": {
						"name": "@laurentsimon/provenance-npm-test",
						"version": "1.0.0",
						"registry": "https://registry.npmjs.org"
					  }
					}`)),
				},
			},
			version: "1.0",
			err:     serrors.ErrorMismatchPackageVersion,
		},
		{
			name: "incorrect patch version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
					  "predicate": {
						"name": "@laurentsimon/provenance-npm-test",
						"version": "1.0.0",
						"registry": "https://registry.npmjs.org"
					  }
					}`)),
				},
			},
			version: "1.0.1",
			err:     serrors.ErrorMismatchPackageVersion,
		},
		{
			name: "incorrect minor version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
					  "predicate": {
						"name": "@laurentsimon/provenance-npm-test",
						"version": "1.0.0",
						"registry": "https://registry.npmjs.org"
					  }
					}`)),
				},
			},
			version: "1.1.0",
			err:     serrors.ErrorMismatchPackageVersion,
		},
		{
			name: "incorrect major version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
					  "predicate": {
						"name": "@laurentsimon/provenance-npm-test",
						"version": "1.0.0",
						"registry": "https://registry.npmjs.org"
					  }
					}`)),
				},
			},
			version: "2.0.0",
			err:     serrors.ErrorMismatchPackageVersion,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := verifyPublishSubjectVersion(tt.att, tt.version)

			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_verifyProvenanceSubjectVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		builderID string
		att       *SignedAttestation
		version   string
		err       error
	}{
		{
			name:      "correct version",
			builderID: common.NpmCLIHostedBuilderID,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "subject": [
						{
						  "name": "pkg:npm/%40laurentsimon/provenance-npm-test@1.0.0",
						  "digest": {
							"sha512": "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20"
						  }
						}
					  ],
					  "predicateType": "https://slsa.dev/provenance/v0.2",
					  "predicate": {
						"buildType": "https://github.com/npm/cli/gha@v1",
						"builder": {
						  "id": "https://github.com/npm/cli@9.5.0"
						}
					  }
					}`)),
				},
			},
			version: "1.0.0",
		},
		{
			name:      "incorrect subset version",
			builderID: common.NpmCLIHostedBuilderID,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "subject": [
						{
						  "name": "pkg:npm/%40laurentsimon/provenance-npm-test@1.0.0",
						  "digest": {
							"sha512": "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20"
						  }
						}
					  ],
					  "predicateType": "https://slsa.dev/provenance/v0.2",
					  "predicate": {
						"buildType": "https://github.com/npm/cli/gha@v1",
						"builder": {
						  "id": "https://github.com/npm/cli@9.5.0"
						}
					  }
					}`)),
				},
			},
			version: "1.0",
			err:     serrors.ErrorMismatchPackageVersion,
		},
		{
			name:      "incorrect patch version",
			builderID: common.NpmCLIHostedBuilderID,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "subject": [
						{
						  "name": "pkg:npm/%40laurentsimon/provenance-npm-test@1.0.0",
						  "digest": {
							"sha512": "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20"
						  }
						}
					  ],
					  "predicateType": "https://slsa.dev/provenance/v0.2",
					  "predicate": {
						"buildType": "https://github.com/npm/cli/gha@v1",
						"builder": {
						  "id": "https://github.com/npm/cli@9.5.0"
						}
					  }
					}`)),
				},
			},
			version: "1.0.1",
			err:     serrors.ErrorMismatchPackageVersion,
		},
		{
			name:      "incorrect minor version",
			builderID: common.NpmCLIHostedBuilderID,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "subject": [
						{
						  "name": "pkg:npm/%40laurentsimon/provenance-npm-test@1.0.0",
						  "digest": {
							"sha512": "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20"
						  }
						}
					  ],
					  "predicateType": "https://slsa.dev/provenance/v0.2",
					  "predicate": {
						"buildType": "https://github.com/npm/cli/gha@v1",
						"builder": {
						  "id": "https://github.com/npm/cli@9.5.0"
						}
					  }
					}`)),
				},
			},
			version: "1.1.0",
			err:     serrors.ErrorMismatchPackageVersion,
		},
		{
			name:      "incorrect major version",
			builderID: common.NpmCLIHostedBuilderID,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "subject": [
						{
						  "name": "pkg:npm/%40laurentsimon/provenance-npm-test@1.0.0",
						  "digest": {
							"sha512": "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20"
						  }
						}
					  ],
					  "predicateType": "https://slsa.dev/provenance/v0.2",
					  "predicate": {
						"buildType": "https://github.com/npm/cli/gha@v1",
						"builder": {
						  "id": "https://github.com/npm/cli@9.5.0"
						}
					  }
					}`)),
				},
			},
			version: "2.0.0",
			err:     serrors.ErrorMismatchPackageVersion,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			builderID, err := utils.TrustedBuilderIDNew(tt.builderID, false)
			if err != nil {
				panic(err)
			}

			err = verifyProvenanceSubjectVersion(builderID, tt.att, tt.version)
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_verifyPublishSubjectName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		att     *SignedAttestation
		subject string
		err     error
	}{
		{
			name: "correct name",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdCIsCiAgICAidmVyc2lvbiI6ICIxLjAuMCIsCiAgICAicmVnaXN0cnkiOiAiaHR0cHM6Ly9yZWdpc3RyeS5ucG1qcy5vcmciCiAgfQp9Cg==",
				},
			},
			subject: "@laurentsimon/provenance-npm-test",
		},
		{
			name: "incorrect name",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdCIsCiAgICAidmVyc2lvbiI6ICIxLjAuMCIsCiAgICAicmVnaXN0cnkiOiAiaHR0cHM6Ly9yZWdpc3RyeS5ucG1qcy5vcmciCiAgfQp9Cg==",
				},
			},
			subject: "wrong name",
			err:     serrors.ErrorMismatchPackageName,
		},
		{
			name: "incorrect scope",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdCIsCiAgICAidmVyc2lvbiI6ICIxLjAuMCIsCiAgICAicmVnaXN0cnkiOiAiaHR0cHM6Ly9yZWdpc3RyeS5ucG1qcy5vcmciCiAgfQp9Cg==",
				},
			},
			subject: "laurentsimon/provenance-npm-test",
			err:     serrors.ErrorMismatchPackageName,
		},
		{
			name: "incorrect with version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdCIsCiAgICAidmVyc2lvbiI6ICIxLjAuMCIsCiAgICAicmVnaXN0cnkiOiAiaHR0cHM6Ly9yZWdpc3RyeS5ucG1qcy5vcmciCiAgfQp9Cg==",
				},
			},
			subject: "@laurentsimon/provenance-npm-test@1.0.0",
			err:     serrors.ErrorMismatchPackageName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := verifyPublishSubjectName(tt.att, tt.subject)

			if !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyPublishPredicateName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		att     *SignedAttestation
		subject string
		err     error
	}{
		{
			name: "correct name",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
			subject: "@laurentsimon/provenance-npm-test-pred",
		},
		{
			name: "incorrect name",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
			subject: "wrong name",
			err:     serrors.ErrorMismatchPackageName,
		},
		{
			name: "incorrect scope",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
			subject: "laurentsimon/provenance-npm-test-pred",
			err:     serrors.ErrorMismatchPackageName,
		},
		{
			name: "incorrect with version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
			subject: "@laurentsimon/provenance-npm-test-pred@1.0.0",
			err:     serrors.ErrorMismatchPackageName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := verifyPublishPredicateName(tt.att, tt.subject)

			if !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyPublishPredicateVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		att     *SignedAttestation
		version string
		err     error
	}{
		{
			name: "correct version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
			version: "1.0.0",
		},
		{
			name: "incorrect subset version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
			version: "1.0",
			err:     serrors.ErrorMismatchPackageVersion,
		},
		{
			name: "incorrect patch version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
			version: "1.0.1",
			err:     serrors.ErrorMismatchPackageVersion,
		},
		{
			name: "incorrect minor version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
			version: "1.1.0",
			err:     serrors.ErrorMismatchPackageVersion,
		},
		{
			name: "incorrect major version",
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
			version: "2.0.0",
			err:     serrors.ErrorMismatchPackageVersion,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := verifyPublishPredicateVersion(tt.att, tt.version)

			if !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyProvenanceSubjectName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		builderID string
		att       *SignedAttestation
		subject   string
		err       error
	}{
		{
			name:      "correct name",
			builderID: common.NpmCLIHostedBuilderID,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "subject": [
						{
						  "name": "pkg:npm/%40laurentsimon/provenance-npm-test@1.0.0",
						  "digest": {
							"sha512": "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20"
						  }
						}
					  ],
					  "predicateType": "https://slsa.dev/provenance/v0.2",
					  "predicate": {
						"buildType": "https://github.com/npm/cli/gha@v1",
						"builder": {
						  "id": "https://github.com/npm/cli@9.5.0"
						}
					  }
					}`)),
				},
			},
			subject: "@laurentsimon/provenance-npm-test",
		},
		{
			name:      "incorrect name",
			builderID: common.NpmCLIHostedBuilderID,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "subject": [
						{
						  "name": "pkg:npm/%40laurentsimon/provenance-npm-test@1.0.0",
						  "digest": {
							"sha512": "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20"
						  }
						}
					  ],
					  "predicateType": "https://slsa.dev/provenance/v0.2",
					  "predicate": {
						"buildType": "https://github.com/npm/cli/gha@v1",
						"builder": {
						  "id": "https://github.com/npm/cli@9.5.0"
						}
					  }
					}`)),
				},
			},
			subject: "wrong name",
			err:     serrors.ErrorMismatchPackageName,
		},
		{
			name:      "incorrect scope",
			builderID: common.NpmCLIHostedBuilderID,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "subject": [
						{
						  "name": "pkg:npm/%40laurentsimon/provenance-npm-test@1.0.0",
						  "digest": {
							"sha512": "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20"
						  }
						}
					  ],
					  "predicateType": "https://slsa.dev/provenance/v0.2",
					  "predicate": {
						"buildType": "https://github.com/npm/cli/gha@v1",
						"builder": {
						  "id": "https://github.com/npm/cli@9.5.0"
						}
					  }
					}`)),
				},
			},
			subject: "laurentsimon/provenance-npm-test",
			err:     serrors.ErrorMismatchPackageName,
		},
		{
			name:      "incorrect with version",
			builderID: common.NpmCLIHostedBuilderID,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload: base64.StdEncoding.EncodeToString([]byte(`{
					  "_type": "https://in-toto.io/Statement/v0.1",
					  "subject": [
						{
						  "name": "pkg:npm/%40laurentsimon/provenance-npm-test@1.0.0",
						  "digest": {
							"sha512": "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20"
						  }
						}
					  ],
					  "predicateType": "https://slsa.dev/provenance/v0.2",
					  "predicate": {
						"buildType": "https://github.com/npm/cli/gha@v1",
						"builder": {
						  "id": "https://github.com/npm/cli@9.5.0"
						}
					  }
					}`)),
				},
			},
			subject: "@laurentsimon/provenance-npm-test@1.0.0",
			err:     serrors.ErrorMismatchPackageName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			builderID, err := utils.TrustedBuilderIDNew(tt.builderID, false)
			if err != nil {
				panic(err)
			}

			err = verifyProvenanceSubjectName(builderID, tt.att, tt.subject)
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_verifyPackageName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	trustedRoot, err := utils.GetSigstoreTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		subject string
		err     error
	}{
		{
			name:    "correct name",
			path:    "npm-attestations.intoto.sigstore",
			subject: "@laurentsimon/provenance-npm-test",
		},
		{
			name:    "incorrect name",
			path:    "npm-attestations.intoto.sigstore",
			subject: "wrong name",
			err:     serrors.ErrorMismatchPackageName,
		},
		{
			name:    "incorrect scope",
			path:    "npm-attestations.intoto.sigstore",
			subject: "laurentsimon/provenance-npm-test",
			err:     serrors.ErrorMismatchPackageName,
		},
		{
			name:    "incorrect with version",
			path:    "npm-attestations.intoto.sigstore",
			subject: "@laurentsimon/provenance-npm-test@1.0.0",
			err:     serrors.ErrorMismatchPackageName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(filepath.Join("testdata", tt.path))
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			npm, err := NpmNew(ctx, trustedRoot, content, clientOpts)
			if err != nil {
				panic(fmt.Errorf("NpmNew: %w", err))
			}
			// Set provenance attestation.
			env, err := getEnvelopeFromBundleBytes(npm.provenanceAttestation.BundleBytes)
			if err != nil {
				panic(fmt.Errorf("getEnvelopeFromBundleBytes: %w", err))
			}
			npm.verifiedProvenanceAtt = &SignedAttestation{
				Envelope: env,
			}

			env, err = getEnvelopeFromBundleBytes(npm.publishAttestation.BundleBytes)
			if err != nil {
				panic(fmt.Errorf("getEnvelopeFromBundleBytes: %w", err))
			}
			npm.verifiedPublishAtt = &SignedAttestation{
				Envelope: env,
			}

			npm.verifiedBuilderID, err = utils.TrustedBuilderIDNew(common.NpmCLIHostedBuilderID, false)
			if err != nil {
				panic(err)
			}

			err = npm.verifyPackageName(&tt.subject)
			if !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyPublishAttestationSubjectDigest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	trustedRoot, err := utils.GetSigstoreTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		hash string
		err  error
	}{
		{
			name: "correct hash",
			path: "npm-attestations.intoto.sigstore",
			hash: "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20",
		},
		{
			name: "incorrect hash",
			path: "npm-attestations.intoto.sigstore",
			hash: "39d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20",
			err:  serrors.ErrorMismatchHash,
		},
		{
			name: "no subjects",
			path: "npm-att-publish-nosubjects.intoto.sigstore",
			hash: "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20",
			err:  serrors.ErrorInvalidDssePayload,
		},
		{
			name: "no digest",
			path: "npm-att-publish-nodigest.intoto.sigstore",
			hash: "29d19f26233f4441328412b34fd73ed104ecfef62f14097890cccf7455b521b65c5acff851849faa85c85395aa22d401436f01f3afb61b19c780e906c88c7f20",
			err:  serrors.ErrorMismatchHash,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(filepath.Join("testdata", tt.path))
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			npm, err := NpmNew(ctx, trustedRoot, content, clientOpts)
			if err != nil {
				panic(fmt.Errorf("NpmNew: %w", err))
			}
			// Set provenance attestation.
			env, err := getEnvelopeFromBundleBytes(npm.provenanceAttestation.BundleBytes)
			if err != nil {
				panic(fmt.Errorf("getEnvelopeFromBundleBytes: %w", err))
			}
			npm.verifiedProvenanceAtt = &SignedAttestation{
				Envelope: env,
			}

			env, err = getEnvelopeFromBundleBytes(npm.publishAttestation.BundleBytes)
			if err != nil {
				panic(fmt.Errorf("getEnvelopeFromBundleBytes: %w", err))
			}
			npm.verifiedPublishAtt = &SignedAttestation{
				Envelope: env,
			}

			err = npm.verifyPublishAttestationSubjectDigest(tt.hash)
			if !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyPackageVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	trustedRoot, err := utils.GetSigstoreTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		version string
		err     error
	}{
		{
			name:    "correct name",
			path:    "npm-attestations.intoto.sigstore",
			version: "1.0.0",
		},
		{
			name:    "incorrect patch",
			path:    "npm-attestations.intoto.sigstore",
			version: "1.0.1",
			err:     serrors.ErrorMismatchPackageVersion,
		},
		{
			name:    "incorrect minor",
			path:    "npm-attestations.intoto.sigstore",
			version: "1.1.0",
			err:     serrors.ErrorMismatchPackageVersion,
		},
		{
			name:    "incorrect major",
			path:    "npm-attestations.intoto.sigstore",
			version: "2.0.0",
			err:     serrors.ErrorMismatchPackageVersion,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(filepath.Join("testdata", tt.path))
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			npm, err := NpmNew(ctx, trustedRoot, content, clientOpts)
			if err != nil {
				panic(fmt.Errorf("NpmNew: %w", err))
			}
			// Set provenance attestation.
			env, err := getEnvelopeFromBundleBytes(npm.provenanceAttestation.BundleBytes)
			if err != nil {
				panic(fmt.Errorf("getEnvelopeFromBundleBytes: %w", err))
			}
			npm.verifiedProvenanceAtt = &SignedAttestation{
				Envelope: env,
			}

			npm.verifiedBuilderID, err = utils.TrustedBuilderIDNew(common.NpmCLIHostedBuilderID, false)
			if err != nil {
				panic(err)
			}

			env, err = getEnvelopeFromBundleBytes(npm.publishAttestation.BundleBytes)
			if err != nil {
				panic(fmt.Errorf("getEnvelopeFromBundleBytes: %w", err))
			}
			npm.verifiedPublishAtt = &SignedAttestation{
				Envelope: env,
			}

			err = npm.verifyPackageVersion(&tt.version)
			if !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyIntotoTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		att            *SignedAttestation
		predicateType  string
		predicateTypes map[string]bool
		payloadType    string
		prefix         bool
		err            error
	}{
		{
			name:           "prov correct v0.2",
			predicateTypes: provenancePredicates,
			payloadType:    intoto.PayloadType,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJzdWJqZWN0IjogWwogICAgewogICAgICAibmFtZSI6ICJwa2c6bnBtLyU0MGxhdXJlbnRzaW1vbi9wcm92ZW5hbmNlLW5wbS10ZXN0QDEuMC4wIiwKICAgICAgImRpZ2VzdCI6IHsKICAgICAgICAic2hhNTEyIjogIjI5ZDE5ZjI2MjMzZjQ0NDEzMjg0MTJiMzRmZDczZWQxMDRlY2ZlZjYyZjE0MDk3ODkwY2NjZjc0NTViNTIxYjY1YzVhY2ZmODUxODQ5ZmFhODVjODUzOTVhYTIyZDQwMTQzNmYwMWYzYWZiNjFiMTljNzgwZTkwNmM4OGM3ZjIwIgogICAgICB9CiAgICB9CiAgXSwKICAicHJlZGljYXRlVHlwZSI6ICJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjAuMiIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJidWlsZFR5cGUiOiAiaHR0cHM6Ly9naXRodWIuY29tL25wbS9jbGkvZ2hhQHYxIiwKICAgICJidWlsZGVyIjogewogICAgICAiaWQiOiAiaHR0cHM6Ly9naXRodWIuY29tL25wbS9jbGlAOS41LjAiCiAgICB9CiAgfQp9Cg==",
				},
			},
		},
		{
			name:           "prov correct v1",
			predicateTypes: provenancePredicates,
			payloadType:    intoto.PayloadType,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoicGtnOm5wbS9zaWdzdG9yZUAyLjMuMSIsImRpZ2VzdCI6eyJzaGE1MTIiOiJmMDZmYmY1YzM1M2NjMGRiMDkzOTA0YjljYWMwZDUzYjQxMmQ4M2RmZjZiODBlNjA0N2Q5Nzg2NzA4YTM4ZTVjMzEwNWNhZDRlOTEzZGZjMjJkYmU4Yzk5OWIzZmUwMjlkNDc5NjlmZTc1NDA2ODQzYjgxNjNkYjZmZDIyZjY4MSJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjEiLCJwcmVkaWNhdGUiOnsiYnVpbGREZWZpbml0aW9uIjp7ImJ1aWxkVHlwZSI6Imh0dHBzOi8vc2xzYS1mcmFtZXdvcmsuZ2l0aHViLmlvL2dpdGh1Yi1hY3Rpb25zLWJ1aWxkdHlwZXMvd29ya2Zsb3cvdjEiLCJleHRlcm5hbFBhcmFtZXRlcnMiOnsid29ya2Zsb3ciOnsicmVmIjoicmVmcy9oZWFkcy9tYWluIiwicmVwb3NpdG9yeSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS9zaWdzdG9yZS1qcyIsInBhdGgiOiIuZ2l0aHViL3dvcmtmbG93cy9yZWxlYXNlLnltbCJ9fSwiaW50ZXJuYWxQYXJhbWV0ZXJzIjp7ImdpdGh1YiI6eyJldmVudF9uYW1lIjoicHVzaCIsInJlcG9zaXRvcnlfaWQiOiI0OTU1NzQ1NTUiLCJyZXBvc2l0b3J5X293bmVyX2lkIjoiNzEwOTYzNTMifX0sInJlc29sdmVkRGVwZW5kZW5jaWVzIjpbeyJ1cmkiOiJnaXQraHR0cHM6Ly9naXRodWIuY29tL3NpZ3N0b3JlL3NpZ3N0b3JlLWpzQHJlZnMvaGVhZHMvbWFpbiIsImRpZ2VzdCI6eyJnaXRDb21taXQiOiI0NmU3MDU2ZmY5OTEyZWJmZWU1Mjk4ZDk0MDI0ODk1YTlmZWE3NmMwIn19XX0sInJ1bkRldGFpbHMiOnsiYnVpbGRlciI6eyJpZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9hY3Rpb25zL3J1bm5lci9naXRodWItaG9zdGVkIn0sIm1ldGFkYXRhIjp7Imludm9jYXRpb25JZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS9zaWdzdG9yZS1qcy9hY3Rpb25zL3J1bnMvOTExNjQwNTc2Ni9hdHRlbXB0cy8xIn19fX0=",
				},
			},
		},
		{
			name:           "prov mismatch payload type",
			predicateTypes: provenancePredicates,
			payloadType:    intoto.PayloadType,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+jso",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJzdWJqZWN0IjogWwogICAgewogICAgICAibmFtZSI6ICJwa2c6bnBtLyU0MGxhdXJlbnRzaW1vbi9wcm92ZW5hbmNlLW5wbS10ZXN0QDEuMC4wIiwKICAgICAgImRpZ2VzdCI6IHsKICAgICAgICAic2hhNTEyIjogIjI5ZDE5ZjI2MjMzZjQ0NDEzMjg0MTJiMzRmZDczZWQxMDRlY2ZlZjYyZjE0MDk3ODkwY2NjZjc0NTViNTIxYjY1YzVhY2ZmODUxODQ5ZmFhODVjODUzOTVhYTIyZDQwMTQzNmYwMWYzYWZiNjFiMTljNzgwZTkwNmM4OGM3ZjIwIgogICAgICB9CiAgICB9CiAgXSwKICAicHJlZGljYXRlVHlwZSI6ICJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjAuMiIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJidWlsZFR5cGUiOiAiaHR0cHM6Ly9naXRodWIuY29tL25wbS9jbGkvZ2hhQHYxIiwKICAgICJidWlsZGVyIjogewogICAgICAiaWQiOiAiaHR0cHM6Ly9naXRodWIuY29tL25wbS9jbGlAOS41LjAiCiAgICB9CiAgfQp9Cg==",
				},
			},
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name:           "prov mismatch predicate type",
			predicateTypes: mismatchProvenancePredicates,
			payloadType:    intoto.PayloadType,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJzdWJqZWN0IjogWwogICAgewogICAgICAibmFtZSI6ICJwa2c6bnBtLyU0MGxhdXJlbnRzaW1vbi9wcm92ZW5hbmNlLW5wbS10ZXN0QDEuMC4wIiwKICAgICAgImRpZ2VzdCI6IHsKICAgICAgICAic2hhNTEyIjogIjI5ZDE5ZjI2MjMzZjQ0NDEzMjg0MTJiMzRmZDczZWQxMDRlY2ZlZjYyZjE0MDk3ODkwY2NjZjc0NTViNTIxYjY1YzVhY2ZmODUxODQ5ZmFhODVjODUzOTVhYTIyZDQwMTQzNmYwMWYzYWZiNjFiMTljNzgwZTkwNmM4OGM3ZjIwIgogICAgICB9CiAgICB9CiAgXSwKICAicHJlZGljYXRlVHlwZSI6ICJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjAuMiIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJidWlsZFR5cGUiOiAiaHR0cHM6Ly9naXRodWIuY29tL25wbS9jbGkvZ2hhQHYxIiwKICAgICJidWlsZGVyIjogewogICAgICAiaWQiOiAiaHR0cHM6Ly9naXRodWIuY29tL25wbS9jbGlAOS41LjAiCiAgICB9CiAgfQp9Cg==",
				},
			},
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name:           "publish correct",
			predicateTypes: publishPredicates,
			prefix:         true,
			payloadType:    intoto.PayloadType,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
		},
		{
			name:           "publish mismatch payload type",
			predicateTypes: publishPredicates,
			prefix:         true,
			payloadType:    intoto.PayloadType,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+jso",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name:           "publish mismatch predicate type",
			predicateTypes: mismatchPublishPredicates,
			prefix:         true,
			payloadType:    intoto.PayloadType,
			att: &SignedAttestation{
				Envelope: &dsselib.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     "ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImh0dHBzOi8vZ2l0aHViLmNvbS9ucG0vYXR0ZXN0YXRpb24vdHJlZS9tYWluL3NwZWNzL3B1Ymxpc2gvdjAuMSIsCiAgInByZWRpY2F0ZSI6IHsKICAgICJuYW1lIjogIkBsYXVyZW50c2ltb24vcHJvdmVuYW5jZS1ucG0tdGVzdC1wcmVkIiwKICAgICJ2ZXJzaW9uIjogIjEuMC4wIiwKICAgICJyZWdpc3RyeSI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZyIKICB9Cn0K",
				},
			},
			err: serrors.ErrorInvalidDssePayload,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := verifyIntotoTypes(tt.att, tt.predicateTypes, tt.payloadType, tt.prefix)
			if !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_verifyIntotoHeaders(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	trustedRoot, err := utils.GetSigstoreTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		version string
		err     error
	}{
		{
			name: "correct",
			path: "npm-attestations.intoto.sigstore",
		},
		{
			name: "prov incorrect stmt predicate type",
			path: "npm-stmt-mismatch-prov-predicatetype.intoto.sigstore",
			err:  serrors.ErrorInvalidDssePayload,
		},
		{
			name: "prov incorrect stmt type",
			path: "npm-stmt-mismatch-prov-type.intoto.sigstore",
			err:  serrors.ErrorInvalidDssePayload,
		},
		{
			name: "prov incorrect att payload type",
			path: "npm-att-mismatch-prov-payloadtype.intoto.sigstore",
			err:  serrors.ErrorInvalidDssePayload,
		},
		{
			name: "pub incorrect stmt predicate type",
			path: "npm-stmt-mismatch-pub-predicatetype.intoto.sigstore",
			err:  serrors.ErrorInvalidDssePayload,
		},
		{
			name: "pub incorrect att payload type",
			path: "npm-att-mismatch-pub-payloadtype.intoto.sigstore",
			err:  serrors.ErrorInvalidDssePayload,
		},
		{
			name: "pub incorrect stmt type",
			path: "npm-stmt-mismatch-pub-type.intoto.sigstore",
			err:  serrors.ErrorInvalidDssePayload,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(filepath.Join("testdata", tt.path))
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			npm, err := NpmNew(ctx, trustedRoot, content, clientOpts)
			if err != nil {
				panic(fmt.Errorf("NpmNew: %w", err))
			}
			// Set provenance attestation.
			env, err := getEnvelopeFromBundleBytes(npm.provenanceAttestation.BundleBytes)
			if err != nil {
				panic(fmt.Errorf("getEnvelopeFromBundleBytes: %w", err))
			}
			npm.verifiedProvenanceAtt = &SignedAttestation{
				Envelope: env,
			}

			env, err = getEnvelopeFromBundleBytes(npm.publishAttestation.BundleBytes)
			if err != nil {
				panic(fmt.Errorf("getEnvelopeFromBundleBytes: %w", err))
			}
			npm.verifiedPublishAtt = &SignedAttestation{
				Envelope: env,
			}

			err = npm.verifyIntotoHeaders()
			if !errCmp(err, tt.err) {
				t.Error(cmp.Diff(err, tt.err))
			}
		})
	}
}

func Test_NpmNew(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	trustedRoot, err := utils.GetSigstoreTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		version string
		err     error
	}{
		{
			name: "correct",
			path: "npm-attestations.intoto.sigstore",
		},
		{
			name: "prov incorrect att predicate type",
			path: "npm-att-mismatch-prov-predicatetype.intoto.sigstore",
			err:  errrorInvalidAttestations,
		},
		{
			name: "publish incorrect att predicate type",
			path: "npm-att-mismatch-pub-predicatetype.intoto.sigstore",
			err:  errrorInvalidAttestations,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(filepath.Join("testdata", tt.path))
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			_, err = NpmNew(ctx, trustedRoot, content, clientOpts)
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_verifyPublishAttestationSignature(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	trustedRoot, err := utils.GetSigstoreTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		version string
		err     error
	}{
		{
			name: "correct",
			path: "npm-attestations.intoto.sigstore",
		},
		{
			name: "incorrect signature",
			path: "npm-att-publish-invalid-signature.intoto.sigstore",
			err:  serrors.ErrorInvalidSignature,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(filepath.Join("testdata", tt.path))
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			npm, err := NpmNew(ctx, trustedRoot, content, clientOpts)
			if err != nil {
				t.Fatalf("unexpected error: \n%s", err)
			}
			err = npm.verifyPublishAttestationSignature()
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_verifyProvenanceAttestationSignature(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	trustedRoot, err := utils.GetSigstoreTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		version string
		err     error
	}{
		{
			name: "correct",
			path: "npm-attestations.intoto.sigstore",
		},
		{
			name: "incorrect signature",
			path: "npm-att-prov-invalid-signature.intoto.sigstore",
			err:  serrors.ErrorInvalidSignature,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(filepath.Join("testdata", tt.path))
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			npm, err := NpmNew(ctx, trustedRoot, content, clientOpts)
			if err != nil {
				t.Fatalf("unexpected error: \n%s", err)
			}
			err = npm.verifyProvenanceAttestationSignature()
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}
